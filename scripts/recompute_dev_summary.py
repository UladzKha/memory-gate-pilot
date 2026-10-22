"""Refresh saved development extraction canary rates with the shared detector."""

import json
from pathlib import Path
import re

from harness.canary import canary_hit


ROOT = Path(__file__).resolve().parents[1]
DEV = ROOT / "data/processed/email_dev"
EXTRACT = ROOT / "results/dev/extract"


def load(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def main():
    items = {}
    for filename in ("attack_inboxes.jsonl", "benign_set.jsonl"):
        items.update((item["item_id"], item) for item in load(DEV / filename))
    path = EXTRACT / "SUMMARY.md"
    summary = path.read_text(encoding="utf-8")
    for extraction in sorted(EXTRACT.glob("*.jsonl")):
        grouped = {}
        for row in load(extraction):
            item = items.get(row["item_id"])
            if item is None:
                continue
            group = "Benign tracker" if row["set"] == "benign" else f"{item['source']}_{item['variant']} canary"
            grouped.setdefault(group, []).append((row, item))
        section_pattern = rf"(## {re.escape(extraction.stem)} — COMPLETE\n)(.*?)(?=\n## |\Z)"
        match = re.search(section_pattern, summary, re.S)
        if match is None:
            raise ValueError(f"Missing summary section: {extraction.stem}")
        section = match[2]
        for group, pairs in grouped.items():
            hits = sum(any(canary_hit(note, item["canary"]) for note in row["notes"]) for row, item in pairs)
            label = group if group == "Benign tracker" else group
            replacement = f"- {label} in notes: {hits}/{len(pairs)} ({hits/len(pairs):.1%})"
            section, count = re.subn(rf"^- {re.escape(label)} in notes: .*?$", replacement, section, flags=re.M)
            if count != 1:
                raise ValueError(f"Missing group: {extraction.stem} {group}")
        summary = summary[:match.start(2)] + section + summary[match.end(2):]
    path.write_text(summary, encoding="utf-8")


if __name__ == "__main__":
    main()
