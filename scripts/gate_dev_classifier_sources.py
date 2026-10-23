"""DEV-only classifier block rates by attack source, using all attack items."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path

from harness.canary import canary_hit
from harness.dataset import REPO_ROOT, verify_dataset
from harness.defend import load_extractions
from harness.defenses import build_defense
from harness.extract import load_config


DEV = REPO_ROOT / "data/processed/email_dev"
EXTRACT = REPO_ROOT / "results/dev/extract"
DEFEND = REPO_ROOT / "results/dev/defend"
OUTPUT = REPO_ROOT / "results/dev/classifier_source_scores.json"
CLASSIFIERS = ("prompt_guard", "protectai_deberta")
SOURCES = ("llmail", "injecagent")


def rows(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def render_email(email: dict) -> str:
    """Use the same five email fields and order as the extraction prompt."""
    return (f"From: {email['from']}\nTo: {email['to']}\nDate: {email['date']}\n"
            f"Subject: {email['subject']}\n\n{email['body']}")


def main() -> None:
    verify_dataset("dev")
    config = load_config("dev")
    attacks = {item["item_id"]: item for item in rows(DEV / "attack_inboxes.jsonl")}
    if len(attacks) != 400 or Counter(item["source"] for item in attacks.values()) != {"llmail": 200, "injecagent": 200}:
        raise ValueError("Unexpected DEV attack set composition")
    result = {"dataset": "dev", "attack_items": len(attacks), "classifiers": {}}
    for condition in CLASSIFIERS:
        defense = build_defense(condition, config)
        by_source = {source: {"raw_blocked": 0, "raw_total": 0, "models": {}}
                     for source in SOURCES}
        for number, item_id in enumerate(sorted(attacks), 1):
            item = attacks[item_id]
            source = item["source"]
            email = item["emails"][item["attack_email_index"]]
            by_source[source]["raw_total"] += 1
            by_source[source]["raw_blocked"] += defense.check(render_email(email)) == "block"
            if number % 50 == 0:
                print(f"{condition}: scored {number}/400 raw DEV injected emails", flush=True)
        for model in config["ollama"]["models"]:
            extractions = {row["item_id"]: row for row in
                           load_extractions(EXTRACT / f"{model}.jsonl", model)}
            saved = {row["item_id"]: row for row in
                     rows(DEFEND / f"{model}__{condition}.jsonl")}
            if set(extractions) != set(saved) or not set(attacks) <= set(extractions):
                raise ValueError(f"Incomplete saved DEV scores: {model} {condition}")
            for item_id, item in attacks.items():
                extraction = extractions[item_id]
                score = saved[item_id]
                if score["extract_prompt_hash"] != extraction["prompt_hash"] or score["set"] != "attack":
                    raise ValueError(f"Stale saved DEV score: {model} {condition} {item_id}")
                blocked_notes = Counter(extraction["notes"]) - Counter(score["memory_notes"])
                bucket = by_source[item["source"]]["models"].setdefault(
                    model, {"canary_notes_blocked": 0, "canary_notes_total": 0})
                for note in extraction["notes"]:
                    if canary_hit(note, item["canary"]):
                        bucket["canary_notes_total"] += 1
                        if blocked_notes[note]:
                            bucket["canary_notes_blocked"] += 1
                            blocked_notes[note] -= 1
        result["classifiers"][condition] = by_source
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT}", flush=True)


if __name__ == "__main__":
    main()
