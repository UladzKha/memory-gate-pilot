"""Validated dataset-v5 extraction overlays for the frozen v2 evaluation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .dataset import REPO_ROOT, verify_dataset
from .defend import load_dataset_items, load_extractions
from .extract import load_config, make_messages, prompt_hash


ROOT = REPO_ROOT / "results/v2"
MODELS = ("qwen3.8:27b", "gemma4:31b", "mistral-small3.2:24b")
INPUT_CONDITIONS = ("promptguard_input", "protectai_input")
PROMPT = REPO_ROOT / "harness/prompts/extractor_system.txt"


def _rows(path: Path, model: str) -> dict[str, dict]:
    rows = load_extractions(path, model)
    result = {row["item_id"]: row for row in rows}
    if any(row.get("error") or row.get("parse_error") for row in rows):
        raise ValueError(f"Errored extraction in {path}")
    return result


def load_items() -> tuple[dict, dict]:
    verify_dataset("eval")
    config = load_config("eval")
    items = load_dataset_items(config)
    if len(items) != 1050:
        raise ValueError("Expected 1,050 dataset-v5 evaluation items")
    return config, items


def load_unfiltered(model: str, items: dict) -> dict[str, dict]:
    template = PROMPT.read_text(encoding="utf-8").rstrip("\n")
    base = _rows(REPO_ROOT / "results/extract" / f"{model}.jsonl", model)
    changed = _rows(ROOT / "extract_v5" / f"{model}.jsonl", model)
    expected = {item_id for item_id, (group, item) in items.items()
                if group in ("attack", "benign") and item["variant"] == "memory"}
    if len(expected) != 337 or set(changed) != expected or set(base) != set(items):
        raise ValueError(f"Incomplete v5 extraction overlay: {model}")
    overlay = {**base, **changed}
    for item_id, (group, item) in items.items():
        current = prompt_hash(make_messages(template, item))
        if overlay[item_id]["prompt_hash"] != current or overlay[item_id]["set"] != group:
            raise ValueError(f"Wrong v5 extractor prompt or set: {model} {item_id}")
        if (base[item_id]["prompt_hash"] == current) != (item_id not in expected):
            raise ValueError(f"Unexpected v1 reuse: {model} {item_id}")
    return overlay


def load_filtered(model: str, condition: str, items: dict,
                  unfiltered: dict[str, dict]) -> dict[str, dict]:
    if condition not in INPUT_CONDITIONS:
        raise ValueError(condition)
    template = PROMPT.read_text(encoding="utf-8").rstrip("\n")
    score_path = ROOT / "input_scores_v5" / f"{condition}.json"
    scores = json.loads(score_path.read_text(encoding="utf-8"))
    config = load_config("eval")
    data_dir = REPO_ROOT / "data/processed/email"
    hashes = {name: hashlib.sha256((data_dir / name).read_bytes()).hexdigest()
              for name in ("attack_inboxes.jsonl", "benign_set.jsonl", "clean_set.jsonl")}
    if (scores["dataset_hashes"] != hashes or len(scores["scores"]) != 6300 or
        scores["threshold"] != config["pins"]["input_classifier_thresholds_dev"][condition]):
        raise ValueError(f"Stale v5 input scores: {condition}")
    changed = _rows(ROOT / "extract_input_v5" / f"{model}__{condition}.jsonl", model)
    expected = set()
    for item_id, (group, item) in items.items():
        dropped = [index for index in range(len(item["emails"]))
                   if scores["scores"][f"{item_id}:{index}"] >= scores["threshold"]]
        if not dropped:
            continue
        expected.add(item_id)
        altered = {**item, "emails": [email for index, email in enumerate(item["emails"])
                                       if index not in dropped]}
        row = changed.get(item_id)
        if not row or row["set"] != group or row["prompt_hash"] != prompt_hash(make_messages(template, altered)):
            raise ValueError(f"Missing or stale filtered extraction: {model} {condition} {item_id}")
        if row["dropped_indices"] != dropped or row["unfiltered_prompt_hash"] != unfiltered[item_id]["prompt_hash"]:
            raise ValueError(f"Wrong filtered provenance: {model} {condition} {item_id}")
    if set(changed) != expected:
        raise ValueError(f"Wrong filtered item set: {model} {condition}")
    return {**unfiltered, **changed}
