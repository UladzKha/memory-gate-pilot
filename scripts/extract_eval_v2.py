"""Evaluation v2 extraction only: v4 changed inboxes and filtered input inboxes.

Never writes the v1 results/extract files. Does not run Level 2 or Level 3.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from harness.dataset import REPO_ROOT, DATASET_FILES, verify_dataset
from harness.defend import load_dataset_items, load_extractions
from harness.defenses import build_defense
from harness.extract import (extract_item, load_config, load_existing, make_messages,
                             post_json, prompt_hash, thinking_control)
from harness.preflight import run_preflight
from scripts.classifier_input_analysis import score_texts


ROOT = REPO_ROOT / "results/v2"
MODELS = ("qwen3.8:27b", "gemma4:31b", "mistral-small3.2:24b")
INPUTS = {"promptguard_input": "prompt_guard", "protectai_input": "protectai_deberta"}
PROMPT_PATH = REPO_ROOT / "harness/prompts/extractor_system.txt"


def item_rows() -> dict[str, tuple[str, dict]]:
    config = load_config("eval")
    verify_dataset("eval")
    items = load_dataset_items(config)
    if len(items) != 1050:
        raise ValueError("Expected 1,050 evaluation items")
    return items


def changed_ids(items: dict) -> set[str]:
    ids = {item_id for item_id, (group, item) in items.items()
           if (group == "attack" and item["variant"] == "memory") or
              (group == "benign" and item["variant"] == "memory")}
    if len(ids) != 337:
        raise ValueError(f"Expected 337 v4 changed inboxes; got {len(ids)}")
    return ids


def dataset_hashes() -> dict[str, str]:
    directory = REPO_ROOT / "data/processed/email"
    return {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in DATASET_FILES}


def append(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        output.flush()
        os.fsync(output.fileno())


def base_extractions(model: str, items: dict, template: str) -> dict[str, dict]:
    frozen_path = REPO_ROOT / "results/extract" / f"{model}.jsonl"
    frozen = {row["item_id"]: row for row in load_extractions(frozen_path, model)}
    if len(frozen) != len(items):
        raise ValueError(f"Incomplete frozen extraction: {model}")
    changed = changed_ids(items)
    for item_id, (_, item) in items.items():
        same = frozen[item_id]["prompt_hash"] == prompt_hash(make_messages(template, item))
        if same != (item_id not in changed):
            raise ValueError(f"Unexpected v1/v4 prompt identity: {model} {item_id}")
    return frozen


def control_for(model: str, config: dict) -> dict:
    show = post_json(config["ollama"]["base_url"], "/api/show", {"model": model}, 60)
    return thinking_control(show)


def extract_changed(model: str) -> None:
    config = load_config("eval")
    items = item_rows()
    template = PROMPT_PATH.read_text(encoding="utf-8").rstrip("\n")
    base_extractions(model, items, template)
    preflight = run_preflight(model, config, "eval")
    out = ROOT / "extract_v4" / f"{model}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    (ROOT / "extract_v4" / f"{model}.preflight.json").write_text(
        json.dumps(preflight, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    existing = load_existing(out, model)
    control = control_for(model, config)
    changed = changed_ids(items)
    for number, item_id in enumerate(sorted(changed), 1):
        group, item = items[item_id]
        expected = prompt_hash(make_messages(template, item))
        prior = existing.get(item_id)
        if prior and prior["prompt_hash"] == expected and not prior.get("error") and not prior.get("parse_error"):
            continue
        result = extract_item(config, model, group, item, template, control)
        if result["prompt_hash"] != expected:
            raise ValueError(f"Extractor prompt mismatch: {item_id}")
        result["dataset_version"] = "dataset-v4"
        append(out, result)
        existing[item_id] = result
        if number % 25 == 0:
            print(f"{model}: v4 extraction {number}/337", flush=True)
    if set(existing) != changed or any(row.get("error") or row.get("parse_error") for row in existing.values()):
        raise RuntimeError(f"Incomplete or errored v4 extraction: {model}")
    print(f"{model}: v4 extraction complete, 337/337 -> {out}", flush=True)


def email_text(email: dict) -> str:
    return f"Subject: {email['subject']}\n\n{email['body']}"


def score_input_emails() -> None:
    config = load_config("eval")
    items = item_rows()
    order = [(item_id, i, email)
             for item_id, (_, item) in sorted(items.items())
             for i, email in enumerate(item["emails"])]
    if len(order) != 6300:
        raise ValueError("Expected 6,300 evaluation email occurrences")
    texts = [email_text(email) for _, _, email in order]
    for condition, classifier in INPUTS.items():
        out = ROOT / "input_scores" / f"{condition}.json"
        threshold = config["pins"]["input_classifier_thresholds_dev"][condition]
        if out.exists():
            current = json.loads(out.read_text(encoding="utf-8"))
            if (current.get("dataset_hashes") != dataset_hashes() or
                current.get("threshold") != threshold or len(current.get("scores", {})) != 6300):
                raise ValueError(f"Stale input scores: {out}")
            print(f"Reusing {out}", flush=True)
            continue
        defense = build_defense(classifier, config)
        scores = score_texts(defense, texts)
        result = {"condition": condition, "classifier": classifier,
                  "model_id": config["defenses"][classifier]["model_id"],
                  "revision": config["defenses"][classifier]["revision"],
                  "threshold": threshold, "calibration": "DEV clean context, <=1% FP",
                  "dataset_hashes": dataset_hashes(),
                  "scores": {f"{item_id}:{i}": score for (item_id, i, _), score in zip(order, scores)}}
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
        print(f"{condition}: scored {len(scores)} evaluation emails -> {out}", flush=True)


def filtered(item_id: str, item: dict, scores: dict) -> tuple[dict, list[int]]:
    dropped = [i for i in range(len(item["emails"]))
               if scores["scores"][f"{item_id}:{i}"] >= scores["threshold"]]
    kept = [email for i, email in enumerate(item["emails"]) if i not in dropped]
    return {**item, "emails": kept}, dropped


def extract_filtered(model: str, condition: str) -> None:
    if condition not in INPUTS:
        raise ValueError(condition)
    config = load_config("eval")
    items = item_rows()
    template = PROMPT_PATH.read_text(encoding="utf-8").rstrip("\n")
    base = base_extractions(model, items, template)
    changed = load_existing(ROOT / "extract_v4" / f"{model}.jsonl", model)
    if set(changed) != changed_ids(items) or any(row.get("error") or row.get("parse_error") for row in changed.values()):
        raise ValueError(f"v4 extraction must be complete before input extraction: {model}")
    overlay = {**base, **changed}
    scores = json.loads((ROOT / "input_scores" / f"{condition}.json").read_text(encoding="utf-8"))
    if scores["dataset_hashes"] != dataset_hashes():
        raise ValueError("Input scores are stale")
    affected = {item_id: (group, altered, dropped)
                for item_id, (group, item) in items.items()
                for altered, dropped in [filtered(item_id, item, scores)] if dropped}
    preflight = run_preflight(model, config, "eval")
    out = ROOT / "extract_input" / f"{model}__{condition}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    (ROOT / "extract_input" / f"{model}__{condition}.preflight.json").write_text(
        json.dumps(preflight, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    existing = load_existing(out, model)
    control = control_for(model, config)
    for number, item_id in enumerate(sorted(affected), 1):
        group, item, dropped = affected[item_id]
        expected = prompt_hash(make_messages(template, item))
        prior = existing.get(item_id)
        if prior and prior["prompt_hash"] == expected and not prior.get("error") and not prior.get("parse_error"):
            continue
        if not item["emails"]:
            result = {"item_id": item_id, "set": group, "model": model, "notes": [],
                      "raw_response": "", "parse_error": False, "error": False,
                      "error_message": None, "prompt_hash": expected,
                      "latency_seconds": 0, "token_counts": {"prompt": 0, "completion": 0},
                      "attempts": [], "empty_reason": "empty_filtered_inbox"}
        else:
            result = extract_item(config, model, group, item, template, control)
        if result["prompt_hash"] != expected:
            raise ValueError(f"Filtered prompt mismatch: {item_id}")
        result.update(condition=condition, dropped_indices=dropped,
                      unfiltered_prompt_hash=overlay[item_id]["prompt_hash"],
                      dataset_version="dataset-v4")
        append(out, result)
        existing[item_id] = result
        if number % 25 == 0:
            print(f"{model} {condition}: filtered extraction {number}/{len(affected)}", flush=True)
    if set(existing) != set(affected) or any(row.get("error") or row.get("parse_error") for row in existing.values()):
        raise RuntimeError(f"Incomplete or errored filtered extraction: {model} {condition}")
    print(f"{model} {condition}: filtered extraction complete, {len(affected)} -> {out}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--score-input", action="store_true")
    parser.add_argument("--model", choices=MODELS)
    parser.add_argument("--input-condition", choices=INPUTS)
    args = parser.parse_args()
    if args.score_input:
        if args.model or args.input_condition:
            parser.error("--score-input takes no model or condition")
        score_input_emails()
    elif args.model and args.input_condition:
        extract_filtered(args.model, args.input_condition)
    elif args.model:
        extract_changed(args.model)
    else:
        parser.error("Choose --score-input or --model")


if __name__ == "__main__":
    main()
