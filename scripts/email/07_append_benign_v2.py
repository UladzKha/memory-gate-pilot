#!/usr/bin/env python3
"""Append the approved v2 benign inboxes without rebuilding frozen v1 rows."""

import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ecommon as E
from common import load_config, make_rng, read_jsonl, write_jsonl
from importlib import import_module

v1 = import_module("06_build_benign_set")


def dev_enron_ids(root):
    ids = set()
    for name in ("attack_inboxes", "benign_set", "clean_set"):
        for row in read_jsonl(root / "data/processed/email_dev" / (name + ".jsonl")):
            ids.update(ep["id"] for ep in row["emails"] if ep["source"] in
                       ("enron-context", "injecagent-attack"))
    return ids


def build():
    root = Path(__file__).resolve().parents[2]
    cfg = load_config()
    inbox_size = cfg["email"]["inbox_size"]
    approved = list(read_jsonl(E.data_path("benign_emails_v2.jsonl")))
    if [r["id"] for r in approved] != [f"benign{i:03d}" for i in range(60, 150)]:
        raise RuntimeError("Final v2 benign file must contain benign060..benign149")
    path = Path(E.data_path("benign_set.jsonl"))
    current = list(read_jsonl(path))
    if [r["item_id"] for r in current[:60]] != [f"benign{i:03d}" for i in range(60)]:
        raise RuntimeError("Frozen v1 benign inbox prefix is missing")
    if len(current) not in (60, 150):
        raise RuntimeError(f"Unexpected benign inbox count: {len(current)}")
    prior_new_ids = {ep["id"] for r in current[60:] for ep in r["emails"]
                     if ep["source"] == "enron-context"}
    clean_tracker = v1.load_tracker("_clean_ctx_used.txt")
    used = (v1.load_tracker("_used_ctx_ids.txt") | clean_tracker |
            dev_enron_ids(root)) - prior_new_ids
    clean_names, owner_map = v1.load_clean_mailbox()
    by_owner = defaultdict(list)
    for pool in [*E.load_pool(), *read_jsonl(E.data_path("enron_v2_context_pool.jsonl"))]:
        if pool["owner"] in owner_map:
            by_owner[pool["owner"]].append(pool)
    for owner in by_owner:
        by_owner[owner].sort(key=lambda row: row["id"])
    owner_counts = Counter(r["owner"] for r in current[:60])
    max_per_owner = E.max_inboxes_per_owner(cfg)
    new = []

    for b in approved:
        available = [(o, [p for p in by_owner[o] if p["id"] not in used])
                     for o in clean_names if owner_counts[o] < max_per_owner]
        available = [(o, pool) for o, pool in available if len(pool) >= inbox_size - 1]
        if not available:
            raise RuntimeError(f"No clean owner has five unused Enron emails for {b['id']}")
        available.sort(key=lambda pair: (owner_counts[pair[0]], -len(pair[1]), pair[0]))
        owner, pool = available[0]
        ctx = pool[:inbox_size - 1]
        owner_counts[owner] += 1
        used.update(p["id"] for p in ctx)
        owner_fake = owner_map[owner]["fake"]
        injected = {
            "id": b["id"], "from": v1.benign_sender(cfg, b["id"]),
            "to": owner_fake,
            "date": E.seeded_injected_date(cfg, "injecteddate.benign." + b["id"],
                                           [p["date"] for p in ctx]),
            "subject": E.benign_subject(b["subject"], cfg, b["id"]),
            "body": E.reformat_benign_body(b["body"], cfg, b["id"]),
            "source": "benign",
        }
        pos = make_rng(cfg, "pos." + b["id"]).randint(1, inbox_size)
        emails = [v1.ctx_row(p, owner_fake) for p in ctx]
        emails.insert(pos - 1, injected)
        new.append({
            "item_id": b["id"], "attack_id": b["id"], "source": "benign",
            "variant": "memory" if b.get("memory_template") else "as_is",
            "carrier": False, "canary": b["tracker"], "owner": owner,
            "owner_fake": owner_fake, "group": "clean", "attack_email_index": pos - 1,
            "emails": emails, "expected_outcome": b["expected_outcome"],
            "expected_not_block": b["expected_not_block"],
        })

    if len(current) == 150:
        if current[60:] != new:
            raise RuntimeError("Existing v2 inboxes differ from deterministic regeneration")
    else:
        with path.open("a", encoding="utf-8", newline="") as stream:
            from common import stable_dump
            for row in new:
                stream.write(stable_dump(row) + "\n")
    tracker_path = Path(E.data_path("_clean_ctx_used.txt"))
    all_clean = sorted(clean_tracker | {ep["id"] for row in new for ep in row["emails"]
                                        if ep["source"] == "enron-context"})
    tracker_path.write_text("\n".join(all_clean) + "\n", encoding="utf-8")
    print(f"benign_set: 150 inboxes; appended/verified 90 v2 items; owner max={max(owner_counts.values())}")
    print(f"new context IDs: {len(new) * 5}; total clean tracker IDs: {len(all_clean)}")


if __name__ == "__main__":
    build()
