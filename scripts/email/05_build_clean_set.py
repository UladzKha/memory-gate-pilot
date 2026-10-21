#!/usr/bin/env python3
"""Build the CLEAN set (email channel): clean-group inboxes, NO injection.

Clean set = the carrier-complement negative control:
  * N inboxes where N = len(attack_inboxes.jsonl) / 2   (600 / 2 = 300, as briefed)
    cross-checked against config email.clean_inboxes;
  * each inbox is exactly inbox_size(6) native {from,to,date,subject,body}
    context emails drawn ONLY from the ``clean`` mailbox group (disjoint from
    the carrier group that hosts the attack inboxes);
  * no attack/canary email and no benign email present - every row is pure
    Enron context with senders faked and the recipient rewritten to the owner;
  * GLOBAL no-reuse: a context email id used anywhere in the dataset
    (attack_inboxes / clean_set / benign_set) is used at most once.

Output: data/processed/email/clean_set.jsonl
Row: {item_id, owner, owner_fake, group, source, emails}. Deterministic.
"""
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ecommon as E  # noqa: E402
from common import load_config, read_jsonl, write_jsonl  # noqa: E402


def load_mailbox():
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


def main():
    cfg = load_config()
    inbox_size = cfg["email"]["inbox_size"]  # 6

    # count = attack items / 2 (as briefed); cross-check the config value.
    attack_items = list(read_jsonl(E.data_path("attack_inboxes.jsonl")))
    n_clean = len(attack_items) // 2
    cfg_clean = int(cfg["email"].get("clean_inboxes", n_clean))
    if cfg_clean != n_clean:
        raise SystemExit(
            f"config email.clean_inboxes={cfg_clean} != attack_items/2={n_clean}; "
            "update config/dataset.yaml")

    clean_names, owner_map = load_mailbox()

    by_owner = defaultdict(list)
    for p in E.load_pool():
        if p["owner"] in owner_map:
            by_owner[p["owner"]].append(p)
    for o in by_owner:
        by_owner[o].sort(key=lambda r: r["id"])

    # GLOBAL no-reuse: never draw a pool id the attack set already consumed.
    # (Disjoint owner groups, so this is normally empty, but the invariant is
    #  honoured.) The clean-group tracker (_clean_ctx_used.txt) is owned by the
    # 600+60 clean+benign build, so it is NOT seeded here.
    used = set()
    atk = E.data_path("_used_ctx_ids.txt")
    if os.path.exists(atk):
        with open(atk) as f:
            used.update(l.strip() for l in f if l.strip())

    usage = defaultdict(set)
    inboxes = defaultdict(int)  # REQ3: inboxes assigned to owner in this set
    max_per_owner = E.max_inboxes_per_owner(cfg)

    def pick_owner(need):
        cand = [o for o in clean_names
                if len(by_owner[o]) - len(usage[o]) >= need
                and inboxes[o] < max_per_owner]
        if not cand:
            raise SystemExit(f"no clean owner has >= {need} ctx and < {max_per_owner} inboxes")
        cand.sort(key=lambda o: (inboxes[o], len(usage[o]) - len(by_owner[o]), o))
        owner = cand[0]
        inboxes[owner] += 1
        return owner

    def take(owner, n):
        avail = [p for p in by_owner[owner] if p["id"] not in usage[owner]][:n]
        if len(avail) < n:
            raise SystemExit(f"{owner}: need {n} unused context, have {len(avail)}")
        usage[owner].update(p["id"] for p in avail)
        return avail

    out = []
    for i in range(n_clean):
        item_id = f"clean{i:03d}"
        owner = pick_owner(inbox_size)
        owner_fake = owner_map[owner]["fake"]
        emails = [ctx_row(p, owner_fake) for p in take(owner, inbox_size)]
        out.append({
            "item_id": item_id,
            "owner": owner,
            "owner_fake": owner_fake,
            "group": "clean",
            "source": "clean",
            "emails": emails,
        })

    out.sort(key=lambda r: r["item_id"])
    write_jsonl(E.data_path("clean_set.jsonl"), out)

    used_clean = {e["id"] for r in out for e in r["emails"]}
    with open(E.data_path("_clean_ctx_used.txt"), "w") as f:
        f.write("\n".join(sorted(used_clean)) + "\n")

    print(f"clean_set: {len(out)} inboxes  (attack_items={len(attack_items)} / 2 = {n_clean})")
    print(f"  inbox_size={inbox_size} | distinct ctx pool ids consumed: {len(used_clean)}")
    print(f"  owners used: {len({r['owner'] for r in out})} (of {len(clean_names)} clean owners)")


if __name__ == "__main__":
    main()
