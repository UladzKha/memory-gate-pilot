"""Frozen v2 Level 2 scoring; writes only results/v2/defend."""

from __future__ import annotations

import argparse
import json
import os

from harness.dataset import REPO_ROOT
from harness.defenses import build_defense
from harness.eval_v2_common import load_filtered, load_items, load_unfiltered
from harness.score import score_item

CONDITIONS = ("none", "promptguard_input", "protectai_input", "promptguard",
              "protectai", "gate_write", "gate_full_tainted", "gate_full_strict")
DEFENSE_NAMES = {"promptguard": "prompt_guard", "protectai": "protectai_deberta",
                 "gate_write": "gate"}


def run_model(model: str) -> None:
    config, items = load_items()
    if model not in config["ollama"]["models"]:
        raise ValueError(model)
    base = load_unfiltered(model, items)
    inputs = {condition: load_filtered(model, condition, items, base)
              for condition in ("promptguard_input", "protectai_input")}
    output = REPO_ROOT / "results/v2/defend"
    output.mkdir(parents=True, exist_ok=True)
    for condition in CONDITIONS:
        path = output / f"{model}__{condition}.jsonl"
        extraction = inputs.get(condition, base)
        if path.exists():
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            if (len(rows) == len(items) and len({row["item_id"] for row in rows}) == len(items)
                    and all(row["condition"] == condition and row["model"] == model
                            and row["extract_prompt_hash"] == extraction[row["item_id"]]["prompt_hash"]
                            for row in rows)):
                print(f"{model} {condition}: reused {len(rows)} rows", flush=True)
                continue
        if condition in ("gate_full_tainted", "gate_full_strict"):
            source = output / f"{model}__gate_write.jsonl"
            rows = [dict(json.loads(line), condition=condition)
                    for line in source.read_text(encoding="utf-8").splitlines()]
        else:
            defense = build_defense(DEFENSE_NAMES.get(condition, "no_defense"), config)
            rows = []
            for item_id, (group, item) in items.items():
                extracted = extraction[item_id]
                scored, _ = score_item(group, item, extracted["notes"], defense)
                scored.update(model=model, condition=condition,
                              extract_prompt_hash=extracted["prompt_hash"])
                rows.append(scored)
        temporary = path.with_suffix(".jsonl.tmp")
        with temporary.open("w", encoding="utf-8") as stream:
            for row in rows:
                stream.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        os.replace(temporary, path)
        print(f"{model} {condition}: scored {len(rows)} rows", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True)
    run_model(parser.parse_args().model)
