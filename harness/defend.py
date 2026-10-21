"""Apply configured defenses to saved extractor results; no extraction calls."""

import argparse
import json
import os
from pathlib import Path
from typing import Any

from .dataset import verify_dataset
from .defenses import build_defense
from .extract import SET_FILES, load_config, path_from_config
from .score import score_item


def load_dataset_items(config: dict[str, Any]) -> dict[str, tuple[str, dict[str, Any]]]:
    items = {}
    for set_name, path_key in SET_FILES:
        with path_from_config(config, path_key).open(encoding="utf-8") as stream:
            for line in stream:
                item = json.loads(line)
                item_id = item["item_id"]
                if item_id in items:
                    raise ValueError(f"Duplicate dataset item_id: {item_id}")
                items[item_id] = (set_name, item)
    return items


def load_extractions(path: Path, model: str) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Run extraction first: {path}")
    rows = []
    seen = set()
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            item_id = row["item_id"]
            if item_id in seen or row["model"] != model:
                raise ValueError(f"Duplicate item or wrong model in {path}: {item_id}")
            if not isinstance(row.get("notes"), list) or any(
                not isinstance(note, str) for note in row["notes"]
            ):
                raise ValueError(f"Invalid saved notes for {item_id}")
            seen.add(item_id)
            rows.append(row)
    if not rows:
        raise ValueError(f"No saved extractions in {path}")
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as output:
        for row in rows:
            output.write(json.dumps(row, ensure_ascii=False) + "\n")
    return temporary


def run_condition(
    model: str, name: str, config: dict[str, Any],
    extractions: list[dict[str, Any]], dataset_items: dict[str, tuple[str, dict[str, Any]]],
) -> tuple[Path, Path]:
    defense = build_defense(name, config)
    scored = []
    quarantined = []
    for extraction in extractions:
        item_id = extraction["item_id"]
        if item_id not in dataset_items:
            raise ValueError(f"Saved extraction has unknown item_id: {item_id}")
        set_name, item = dataset_items[item_id]
        if extraction["set"] != set_name:
            raise ValueError(f"Saved extraction has wrong set: {item_id}")
        result, quarantine = score_item(set_name, item, extraction["notes"], defense)
        result["model"] = model
        result["extract_prompt_hash"] = extraction["prompt_hash"]
        scored.append(result)
        if quarantine:
            quarantined.append({
                "item_id": item_id, "set": set_name, "model": model,
                "condition": name, "notes": quarantine,
            })

    stem = f"{model}__{name}.jsonl"
    output_dir = path_from_config(config, "output_dir")
    score_path = output_dir / "defend" / stem
    quarantine_path = output_dir / "quarantine" / stem
    score_temp = write_jsonl(score_path, scored)
    quarantine_temp = write_jsonl(quarantine_path, quarantined)
    os.replace(quarantine_temp, quarantine_path)
    os.replace(score_temp, score_path)
    return score_path, quarantine_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True, help="Model tag used for saved extraction")
    parser.add_argument(
        "--condition", action="append", help="Run only this configured condition; may repeat"
    )
    args = parser.parse_args()

    verify_dataset()
    config = load_config()
    if args.model not in config["ollama"]["models"]:
        parser.error(f"Model is not listed in harness.yaml: {args.model}")
    conditions = config["defenses"]["conditions"]
    chosen = args.condition or conditions
    if any(name not in conditions for name in chosen):
        parser.error("Requested condition is not enabled in harness.yaml")
    output_dir = path_from_config(config, "output_dir")
    extraction_path = output_dir / "extract" / f"{args.model}.jsonl"
    extractions = load_extractions(extraction_path, args.model)
    dataset_items = load_dataset_items(config)
    for name in chosen:
        score_path, quarantine_path = run_condition(
            args.model, name, config, extractions, dataset_items
        )
        print(f"{name}: {len(extractions)} items -> {score_path}; quarantine -> {quarantine_path}")


if __name__ == "__main__":
    main()
