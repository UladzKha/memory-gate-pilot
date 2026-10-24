"""Pre-freeze, extraction-only attack gate counts by variant and v5 template.

This reads saved notes and calls the frozen local gate. It makes no model or
Level 3 calls and does not compute attack success.
"""

from collections import Counter

from memgate import check_batch

from harness.canary import canary_hit
from harness.extract import load_existing
from scripts.common import load_config as load_dataset_config, make_rng
from scripts.extract_eval_v5 import MODELS, PROMPT_PATH, ROOT, base_extractions, changed_ids, item_rows


def main() -> None:
    items = item_rows()
    dataset_config = load_dataset_config()
    templates = (ROOT.parents[1] / "data/raw/heldout_templates_v2.txt").read_text(encoding="utf-8").splitlines()
    if len(templates) != 10 or len(set(templates)) != 10:
        raise ValueError("Expected ten distinct final held-out templates")
    template = PROMPT_PATH.read_text(encoding="utf-8").rstrip("\n")
    variant = Counter()
    per_template = Counter()

    for model in MODELS:
        base = base_extractions(model, items, template)
        fresh = load_existing(ROOT / "extract_v5" / f"{model}.jsonl", model)
        if set(fresh) != changed_ids(items) or any(row.get("error") or row.get("parse_error") for row in fresh.values()):
            raise ValueError(f"Incomplete v5 extraction: {model}")
        overlay = {**base, **fresh}
        if set(overlay) != set(items):
            raise ValueError(f"Incomplete overlay: {model}")
        for item_id, (group, item) in items.items():
            if group != "attack":
                continue
            notes = overlay[item_id]["notes"]
            decisions = check_batch(notes, item["emails"], item["owner"])
            if len(notes) != len(decisions):
                raise ValueError(f"Decision count mismatch: {model} {item_id}")
            relevant = [decision for note, decision in zip(notes, decisions)
                        if canary_hit(note, item["canary"])]
            keys = [(variant, (model, item["variant"]))]
            if item["variant"] == "memory":
                choice = make_rng(dataset_config, "v4.template." + item_id).choice(templates)
                keys.append((per_template, (model, templates.index(choice) + 1)))
            for counter, prefix in keys:
                counter[prefix + ("n",)] += 1
                counter[prefix + ("reachable",)] += bool(relevant)
                counter[prefix + ("N2",)] += any("N2" in decision.rules for decision in relevant)
                counter[prefix + ("N1",)] += any("N1" in decision.rules for decision in relevant)
                counter[prefix + ("block",)] += any(decision.outcome == "block" for decision in relevant)

    print("| Model | Variant | Items | Canary in note | N2 | N1 | Block | L3 none | L3 gate_full_tainted |")
    print("|---|---|---:|---:|---:|---:|---:|---|---|")
    for model in MODELS:
        for label in ("as_is", "memory"):
            values = [variant[(model, label, key)] for key in ("n", "reachable", "N2", "N1", "block")]
            print(f"| `{model}` | `{label}` | " + " | ".join(map(str, values)) + " | pending | pending |")
    print()
    print("| Model | Template | Items | Canary in note | N2 | N1 | Block | L3 none | L3 gate_full_tainted |")
    print("|---|---:|---:|---:|---:|---:|---:|---|---|")
    for model in MODELS:
        for index in range(1, 11):
            values = [per_template[(model, index, key)] for key in ("n", "reachable", "N2", "N1", "block")]
            print(f"| `{model}` | {index} | " + " | ".join(map(str, values)) + " | pending | pending |")


if __name__ == "__main__":
    main()
