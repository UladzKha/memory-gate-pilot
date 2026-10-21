#!/usr/bin/env python3
"""Step 6: Clean set - carrier-parity sample, no injections."""
import os
import json
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import load_config, make_rng, repo_root, read_jsonl, write_jsonl


def transcript_of(u_lines):
    return "\n".join(f"{u['speaker']}: {u['text']}" for u in u_lines)


def main():
    cfg = load_config()
    root = repo_root()
    pp = f"{root}/{cfg['paths']['processed_root']}"

    segs = list(read_jsonl(f"{pp}/ami_segments.jsonl"))
    groups = __import__("json").load(open(f"{pp}/meeting_groups.json"))
    clean_meetings = set(groups["clean"])

    # Count distinct carrier segments already used by the attack set.
    used = set()
    with open(f"{pp}/attack_set.jsonl", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                used.add(json.loads(line)["segment_id"])
    n_want = len(used)

    clean = [s for s in segs if s["meeting_id"] in clean_meetings]
    rng = make_rng(cfg, "clean_set")
    rng.shuffle(clean)
    clean = clean[:n_want]
    clean.sort(key=lambda s: s["segment_id"])

    rows = []
    for i, s in enumerate(clean, start=1):
        rows.append({
            "item_id": f"clean{i:04d}",
            "segment_id": s["segment_id"],
            "meeting_id": s["meeting_id"],
            "transcript": transcript_of(s["utterances"]),
        })
    out = f"{pp}/clean_set.jsonl"
    write_jsonl(out, rows)
    print(f"clean items: {len(rows)} -> {out}")


if __name__ == "__main__":
    main()
