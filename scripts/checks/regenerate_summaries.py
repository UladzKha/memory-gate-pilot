#!/usr/bin/env python3
"""Regenerate saved extraction summaries from existing rows; never call models."""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from harness.extract import load_config, load_items, path_from_config
from harness.overnight import build_summary


def result_rows(path: Path, model: str) -> dict:
    rows = {}
    for line in path.open(encoding="utf-8"):
        row = json.loads(line)
        if row["model"] != model or row["item_id"] in rows:
            raise ValueError(f"Model mismatch or duplicate item ID in {path}")
        rows[row["item_id"]] = row
    return rows


def regenerate(dataset: str) -> None:
    config = load_config(dataset)
    items = load_items(config, smoke=False)
    out = path_from_config(config, "output_dir") / "extract"
    manifest = json.loads((out / "MANIFEST.json").read_text(encoding="utf-8"))
    old = (out / "SUMMARY.md").read_text(encoding="utf-8")
    parts = []
    for model in config["ollama"]["models"]:
        rows = result_rows(out / f"{model}.jsonl", model)
        if set(rows) != {item["item_id"] for _, item in items}:
            raise ValueError(f"Incomplete or foreign result IDs for {model} in {dataset}")
        block = re.search(rf"^## {re.escape(model)} — .*?(?=^## |\Z)", old,
                          flags=re.MULTILINE | re.DOTALL)
        if not block:
            raise ValueError(f"Missing prior summary section for {model}")
        time_match = re.search(r"^- Total time: ([\d.]+) s$", block.group(), re.MULTILINE)
        if not time_match:
            raise ValueError(f"Missing prior run time for {model}")
        status = (manifest.get("dataset_versions", [{}])[-1].get("models", {}).get(model, {})
                  .get("status") or manifest["models"][model]["status"])
        block = build_summary(model, rows, items, status, float(time_match.group(1)),
                              manifest["commit"], manifest["extractor_prompt_sha256"])
        llmail_commit = manifest.get("current_dataset_commit")
        if llmail_commit:
            tag = "dataset-v3" if dataset == "eval" else "dev-v2"
            block += f"\n- LLMail rows commit: `{llmail_commit}` ({tag})"
        parts.append(block)
    llmail_commit = manifest.get("current_dataset_commit")
    if dataset == "eval" and "dataset_versions" in manifest:
        versions = manifest["dataset_versions"]
        heading = ("# Evaluation extraction summary (dataset-v3)\n\n"
                   f"Dataset commits: `dataset-v1` `{versions[0]['commit']}`; "
                   f"`dataset-v2` `{versions[-1]['commit']}`; "
                   f"`dataset-v3` `{llmail_commit}` (LLMail rows).\n\n"
                   "Each model section's Commit line is the commit recorded for the earlier rows. "
                   "LLMail rows use the dataset-v3 commit on the following line.\n\n")
    else:
        heading = ("# Overnight extraction summary\n\n"
                   f"Dataset commits: `dev-v1` `{manifest['commit']}`; "
                   f"`dev-v2` `{llmail_commit}` (LLMail rows).\n\n"
                   "Each model section's Commit line is the commit recorded for the earlier rows. "
                   "LLMail rows use the dev-v2 commit on the following line.\n\n")
    (out / "SUMMARY.md").write_text(heading + "\n\n".join(parts) + "\n", encoding="utf-8")
    print(f"Regenerated {out / 'SUMMARY.md'} ({len(items)} items per model)")


if __name__ == "__main__":
    for name in ("eval", "dev"):
        regenerate(name)
