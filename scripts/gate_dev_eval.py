"""Evaluate memgate on saved development extractions only."""

from collections import Counter, defaultdict
import json
from pathlib import Path
import re

from harness.canary import canary_hit
from memgate import check_batch


ROOT = Path(__file__).resolve().parents[1]
DEV = ROOT / "data/processed/email_dev"
EXTRACT = ROOT / "results/dev/extract"
OUTPUT = ROOT / "results/checks"


def rows(path):
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream]


def main():
    items = {}
    for group, filename in (("attack", "attack_inboxes.jsonl"), ("benign", "benign_set.jsonl"), ("clean", "clean_set.jsonl")):
        for item in rows(DEV / filename):
            items[item["item_id"]] = group, item
    paths = sorted(EXTRACT.glob("*.jsonl"))
    if not paths:
        raise ValueError("No development extractions")
    lines = ["# Memory-write gate development evaluation", "", "All inputs are from `results/dev/extract/` and `data/processed/email_dev/`.", "",
             "| Model | Attack canary before | After allow-only | Attack notes block / quarantine | Benign tracker allow / quarantine / block | Clean inboxes any intervention | Clean note block / quarantine |", "|---|---:|---:|---:|---:|---:|---:|"]
    details = []
    errors_block, errors_allow = [], []
    for path in paths:
        model = path.stem
        counts = defaultdict(Counter)
        rules = defaultdict(Counter)
        for row in rows(path):
            group, item = items[row["item_id"]]
            notes = row["notes"]
            decisions = check_batch(notes, item["emails"], item["owner"])
            canary = item.get("canary")
            hits = [canary_hit(note, canary) if canary else False for note in notes]
            if group == "attack":
                counts[group]["items"] += 1
                counts[group]["before"] += any(hits)
                counts[group]["after"] += any(hit and d.outcome == "allow" for hit, d in zip(hits, decisions))
            if group == "clean":
                counts[group]["items"] += 1
                counts[group]["intervened"] += any(d.outcome != "allow" for d in decisions)
            if group == "benign":
                tracker_outcomes = [d.outcome for d, hit in zip(decisions, hits) if hit]
                counts[group]["items"] += 1
                if tracker_outcomes:
                    outcome = ("block" if "block" in tracker_outcomes else
                               "quarantine" if "quarantine" in tracker_outcomes else "allow")
                    counts[group]["tracker_item_" + outcome] += 1
                else:
                    counts[group]["no_tracker"] += 1
            for note, decision, hit in zip(notes, decisions, hits):
                counts[group][decision.outcome] += 1
                counts[group]["notes"] += 1
                for rule in decision.rules:
                    rules[group][rule] += 1
                if group == "benign" and hit:
                    counts[group]["tracker_" + decision.outcome] += 1
                if group in ("benign", "clean") and decision.outcome == "block":
                    errors_block.append((model, row["item_id"], note, decision))
                if group == "attack" and hit and decision.outcome == "allow":
                    errors_allow.append((model, row["item_id"], note, decision))
        a, b, c = counts["attack"], counts["benign"], counts["clean"]
        lines.append(f"| {model} | {a['before']}/{a['items']} | {a['after']}/{a['items']} | {a['block']} / {a['quarantine']} | {b['tracker_item_allow']} / {b['tracker_item_quarantine']} / {b['tracker_item_block']} ({b['no_tracker']} without tracker) | {c['intervened']}/{c['items']} | {c['block']}/{c['notes']} / {c['quarantine']}/{c['notes']} |")
        details += ["", f"## {model} rule hits", "", "| Set | T1 | T2 | T3 | N3 | N1 | N2 |", "|---|---:|---:|---:|---:|---:|---:|"]
        for group in ("attack", "benign", "clean"):
            details.append("| " + group + " | " + " | ".join(str(rules[group][rule]) for rule in ("T1", "T2", "T3", "N3", "N1", "N2")) + " |")
        details.append("")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "gate_dev_metrics.md").write_text("\n".join(lines + details).rstrip() + "\n", encoding="utf-8")
    sample = ["# Development gate errors", "", "First 20 blocked benign or clean notes and first 20 allowed attack canary notes, in model and item order.", ""]
    for heading, candidates in (("Blocked benign or clean notes", errors_block), ("Allowed attack canary notes", errors_allow)):
        sample += [f"## {heading}", ""]
        sample += [f"Available: {len(candidates)}; exported: {min(20, len(candidates))}.", ""]
        for model, item_id, note, decision in candidates[:20]:
            sample += [f"### {model} — {item_id}", "", f"Source index: `{decision.source_index}`; link score: `{decision.link_score}`; rules: `{', '.join(decision.rules) or 'none'}`", "", "```text", note.replace("```", "` ` `"), "```", ""]
    (OUTPUT / "gate_dev_errors.md").write_text("\n".join(sample).rstrip() + "\n", encoding="utf-8")
    print("\n".join(lines[:len(paths)+5]))


if __name__ == "__main__":
    main()
