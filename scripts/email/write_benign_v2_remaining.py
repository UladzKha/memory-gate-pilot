#!/usr/bin/env python3
"""Append five individually authored 15-email batches and check each one."""

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from common import read_jsonl, write_jsonl, word_count  # noqa: E402
import ecommon as E  # noqa: E402
from benign_texts import USED_TOPICS  # noqa: E402
from benign_texts_v2 import BATCH as FIRST_BATCH, USED_TOPICS_V2  # noqa: E402
from benign_v2_remaining_content import BATCHES  # noqa: E402

FORBIDDEN = re.compile(r"\b(?:attack|injection|benign|test|canary|tracker|relay)\b", re.I)


def make_row(spec, subject, content):
    body = spec["memory_template"].format(attack=content) if spec["memory_template"] else content
    body = body.format(tracker=spec["tracker"])
    if FORBIDDEN.search(subject + " " + body.replace(spec["tracker"], "")):
        raise RuntimeError(f"{spec['id']}: forbidden word")
    if body.casefold().count(spec["tracker"].casefold()) != 1:
        raise RuntimeError(f"{spec['id']}: target must appear exactly once")
    count = word_count(body)
    low, high = .85 * spec["target_words"], 1.15 * spec["target_words"]
    if not low <= count <= high:
        raise RuntimeError(f"{spec['id']}: {count} words outside {low:.1f}-{high:.1f}")
    return {**spec, "subject": subject, "body": body}


def main():
    specs = {r["id"]: r for r in read_jsonl(E.data_path("benign_specs_v2.jsonl"))}
    original = [make_row(specs[item_id], *FIRST_BATCH[item_id]) for item_id in FIRST_BATCH]
    draft = E.data_path("benign_emails_v2_DRAFT.jsonl")
    if os.path.exists(draft):
        current = list(read_jsonl(draft))
        if current[:15] != original:
            raise RuntimeError("Approved first batch differs from the existing draft")
    topics = list(USED_TOPICS) + list(USED_TOPICS_V2.values())
    rows = list(original)
    for batch_index, batch in enumerate(BATCHES):
        if not batch:
            break
        start = 75 + 15 * batch_index
        expected = [f"benign{i:03d}" for i in range(start, start + 15)]
        if [entry[0] for entry in batch] != expected:
            raise RuntimeError(f"Batch {batch_index + 2} does not contain exactly {expected[0]}..{expected[-1]}")
        for item_id, topic, subject, content in batch:
            if topic in topics:
                raise RuntimeError(f"{item_id}: topic repeated")
            topics.append(topic)
            rows.append(make_row(specs[item_id], subject, content))
        write_jsonl(draft, rows)
        print(f"\n=== Authored batch {start:03d}-{start + 14:03d}; {len(rows)}/90 new emails ===", flush=True)
        for row in rows[-15:]:
            print(f"{row['id']}: {word_count(row['body'])}/{row['target_words']} words", flush=True)
        subprocess.run([sys.executable, os.path.join(HERE, "check_benign.py"), "--v2-draft"], check=True)
    print(f"Complete draft: {draft}")


if __name__ == "__main__":
    main()
