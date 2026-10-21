#!/usr/bin/env python3
"""Inject the 60 APPROVED benign emails into CLEAN-group inboxes (email channel).

The benign class is frozen: data/processed/email/benign_emails.jsonl (60 rows,
id benign000..benign059, tracker + subject + body + expected_outcome +
expected_not_block). The benign authoring scripts (benign_specs.py,
benign_texts.py) predate the approved content and are NOT re-run here.

Injection = SAME logic as the LLMail attack channel (03_build_attack_inboxes):
  * one standalone benign email (the benign row rendered as
    {from,to,date,subject,body,source}) at a SEEDED position 1..6;
  * 5 context emails around it, faked senders, recipient = the inbox owner;
  * a 6-email inbox (inbox_size);
  * clean-group mailboxes ONLY (disjoint from the carrier group) and GLOBAL
    no-reuse of context pool ids (honours _used_ctx_ids.txt + the clean-group
    tracker _clean_ctx_used.txt written by 05_build_clean_set.py).

Output: data/processed/email/benign_set.jsonl
Row: same fields as attack_inboxes.jsonl plus expected_outcome /
     expected_not_block:
  {attack_email_index, attack_id, canary, carrier, emails, group, item_id,
   owner, owner_fake, source, variant, expected_outcome, expected_not_block}
Deterministic (seeded rng, no wall clock, stable JSON).
"""
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ecommon as E  # noqa: E402
from common import make_rng, new_hex8, read_jsonl, write_jsonl, load_config  # noqa: E402

def load_clean_mailbox():
    rows = list(read_jsonl(E.data_path("mailbox_split.jsonl")))
    clean = [r for r in rows if r["group"] == "clean"]
    return [c["owner"] for c in clean], {r["owner"]: r for r in clean}


def ctx_row(pool, owner_fake):
    return {
        "id": pool["id"],
        "from": E.fake_addr(pool["from"]),
        "to": owner_fake,
        "date": pool["date"],
        "subject": pool["subject"],
        "body": pool["body"],
        "source": "enron-context",
    }


def benign_sender(cfg, benign_id):
    """Deterministic fake colleague address for a benign email (privacy)."""
    return f"p_{new_hex8(make_rng(cfg, 'benign.sender.' + benign_id))}@example.org"


def load_tracker(name):
    path = E.data_path(name)
    if not os.path.exists(path):
        return set()
    with open(path) as f:
        return {l.strip() for l in f if l.strip()}


def main():
    cfg = load_config()
    inbox_size = cfg["email"]["inbox_size"]  # 6

    benign = list(read_jsonl(E.data_path("benign_emails.jsonl")))
    benign.sort(key=lambda r: r["id"])

    clean_names, owner_map = load_clean_mailbox()

    by_owner = defaultdict(list)
    for p in E.load_pool():
        if p["owner"] in owner_map:
            by_owner[p["owner"]].append(p)
    for o in by_owner:
        by_owner[o].sort(key=lambda r: r["id"])

    # GLOBAL no-reuse: attack context + clean-set context are off-limits.
    used = load_tracker("_used_ctx_ids.txt") | load_tracker("_clean_ctx_used.txt")
    clean_tracker = load_tracker("_clean_ctx_used.txt")

    usage = defaultdict(set)
    inboxes = defaultdict(int)
    max_per_owner = E.max_inboxes_per_owner(cfg)

    def owner_avail(o):
        return sum(1 for p in by_owner[o] if p["id"] not in usage[o] and p["id"] not in used)

    def pick_owner(need):
        cand = [o for o in clean_names
                if owner_avail(o) >= need
                and inboxes[o] < max_per_owner]
        if not cand:
            raise SystemExit(f"no clean owner has >= {need} globally-unused ctx and < {max_per_owner} benign inboxes")
        cand.sort(key=lambda o: (inboxes[o], -owner_avail(o), o))
        owner = cand[0]
        inboxes[owner] += 1
        return owner

    def take(owner, n):
        avail = [p for p in by_owner[owner]
                 if p["id"] not in usage[owner] and p["id"] not in used][:n]
        if len(avail) < n:
            raise SystemExit(f"{owner}: need {n} unused context, have {len(avail)}")
        usage[owner].update(p["id"] for p in avail)
        return avail

    out = []
    for b in benign:
        item_id = b["id"]
        owner = pick_owner(inbox_size - 1)
        owner_fake = owner_map[owner]["fake"]

        # standalone benign email (same shape/rendering as the LLMail attack email)
        # REQ2: SEEDED injected date between the min/max date of the context emails.
        # FIX2: reformat the frozen flat body into 1-4 paragraphs (greeting and
        # sign-off on their own lines if present; words unchanged) and prefix
        # 'RE: ' to ~20% of subjects, so the benign emails share context's line-
        # break and RE:/FW: surface rates.
        ctx = take(owner, inbox_size - 1)
        att_date = E.seeded_injected_date(
            cfg, "injecteddate.benign." + item_id, [p["date"] for p in ctx])
        att = {
            "id": item_id,
            "from": benign_sender(cfg, item_id),
            "to": owner_fake,
            "date": att_date,
            "subject": E.benign_subject(b["subject"], cfg, item_id),
            "body": E.reformat_benign_body(b["body"], cfg, item_id),
            "source": "benign",
        }
        base = [ctx_row(p, owner_fake) for p in ctx]

        pos = make_rng(cfg, "pos." + item_id).randint(1, inbox_size)
        emails = list(base)
        emails.insert(pos - 1, att)

        out.append({
            "item_id": item_id,
            "attack_id": item_id,
            "source": "benign",
            "variant": "memory" if b.get("memory_template") else "as_is",
            "carrier": False,
            "canary": b["tracker"],
            "owner": owner,
            "owner_fake": owner_fake,
            "group": "clean",
            "attack_email_index": pos - 1,
            "emails": emails,
            "expected_outcome": b["expected_outcome"],
            "expected_not_block": b["expected_not_block"],
        })

    out.sort(key=lambda r: r["item_id"])
    write_jsonl(E.data_path("benign_set.jsonl"), out)

    # fold benign clean-context ids into the shared clean tracker (union)
    benign_ctx = {e["id"] for r in out for e in r["emails"] if e["source"] == "enron-context"}
    all_clean = sorted(clean_tracker | benign_ctx)
    with open(E.data_path("_clean_ctx_used.txt"), "w") as f:
        f.write("\n".join(all_clean) + "\n")

    print(f"benign_set: {len(out)} inboxes (clean group; no-reuse)")
    print(f"  inbox_size={inbox_size} | benign email at seeded pos 1..6")
    print(f"  owners used: {len({r['owner'] for r in out})} (of {len(clean_names)} clean owners)")
    print(f"  expected_outcome: "
          f"allow={sum(1 for r in out if r['expected_outcome'] == 'allow')} "
          f"quarantine={sum(1 for r in out if r['expected_outcome'] == 'quarantine')}")
    print(f"  benign clean-context pool ids: {len(benign_ctx)} "
          f"(clean tracker now {len(all_clean)} ids)")


if __name__ == "__main__":
    main()
