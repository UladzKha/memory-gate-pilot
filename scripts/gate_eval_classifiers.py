"""Score frozen evaluation extractions with the two pinned local classifiers."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from harness.dataset import REPO_ROOT, verify_dataset
from harness.defend import load_dataset_items, load_extractions, run_condition
from harness.extract import load_config


CONDITIONS = ("prompt_guard", "protectai_deberta")


def complete(path: Path, extraction: list[dict], model: str, condition: str) -> bool:
    if not path.exists():
        return False
    expected = {row["item_id"]: row["prompt_hash"] for row in extraction}
    found = {}
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            item_id = row["item_id"]
            if item_id in found or row.get("model") != model or row.get("condition") != condition:
                return False
            found[item_id] = row.get("extract_prompt_hash")
    return found == expected


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True)
    args = parser.parse_args()
    verify_dataset("eval")
    config = load_config("eval")
    if args.model not in config["ollama"]["models"]:
        parser.error("Model is not configured")
    items = load_dataset_items(config)
    extraction = load_extractions(REPO_ROOT / "results/extract" / f"{args.model}.jsonl", args.model)
    if len(items) != 1050 or len(extraction) != 1050:
        raise ValueError("Expected 1,050 frozen evaluation items and extractions")
    for condition in CONDITIONS:
        path = REPO_ROOT / "results/defend" / f"{args.model}__{condition}.jsonl"
        if complete(path, extraction, args.model, condition):
            print(f"{args.model} {condition}: reused complete Level 2 scores", flush=True)
            continue
        score_path, _ = run_condition(args.model, condition, config, extraction, items)
        print(f"{args.model} {condition}: scored {len(extraction)} items -> {score_path}", flush=True)


if __name__ == "__main__":
    main()
