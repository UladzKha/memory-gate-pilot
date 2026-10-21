#!/usr/bin/env python3
"""Split Enron owners into DISJOINT carrier / clean mailbox groups.

- ``carrier``: hosts the two attack sets (600 = 150 llmail x2 + 150 bipia x2).
- ``clean``:   hosts the clean set (300) + benign set (60).
- An owner lands in EXACTLY one group, so carrier items and clean/benign items
  draw from disjoint mailboxes.
- REQ3: each owner may host at most ``email.max_inboxes_per_owner`` (default 10)
  inboxes in ANY one set. So the carrier group needs at least
  ``ceil(attack_inboxes / max_per_owner)`` owners and the clean group at least
  ``ceil((clean_inboxes + benign_count) / max_per_owner)`` owners. We assign the
  DEEPEST owners to carrier (the heavier context demand) and the rest to clean,
  growing the carrier set if the minimum owners lack total email depth.
- Every owner's fake address is emitted for reuse (privacy mapping).
- Deterministic: sorted by (depth desc, owner asc); no wall clock.
"""
import sys
import os
import math

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import load_config, read_jsonl, write_jsonl

import ecommon as E


def main():
    cfg = load_config()
    email = cfg["email"]
    max_per_owner = int(email.get("max_inboxes_per_owner", 10))
    inbox_size = int(email["inbox_size"])

    n_attack = int(email["attack_inboxes"])          # 600
    n_clean = int(email["clean_inboxes"])            # 300
    n_benign = int(email["benign_count"])            # 60

    min_carrier_owners = math.ceil(n_attack / max_per_owner)               # 60
    min_clean_owners = math.ceil((n_clean + n_benign) / max_per_owner)     # 36

    pool = list(read_jsonl(E.data_path("enron_pool.jsonl")))
    depth = {}
    for r in pool:
        depth[r["owner"]] = depth.get(r["owner"], 0) + 1
    owners = sorted(depth, key=lambda o: (-depth[o], o))

    # context emails consumed per set (each inbox draws inbox_size-1 or inbox_size
    # distinct pool ids; use the per-inbox lower bound of inbox_size-1 for every
    # inbox, which is the real minimum for llmail/clean/benign and close for bipia)
    ctx_per_inbox = inbox_size - 1                       # 5
    req_carrier = n_attack * ctx_per_inbox
    req_clean = (n_clean + n_benign) * ctx_per_inbox

    def depth_of(namelist):
        return sum(depth[o] for o in namelist)

    # reserve the minimum carrier owners; grow only if total depth is short
    k = max(min_carrier_owners, 1)
    while k < len(owners) and depth_of(owners[:k]) < max(req_carrier, 0):
        k += 1
    if depth_of(owners[:k]) < max(req_carrier, 0) and k >= len(owners):
        # use everyone if still short, then validate below
        k = len(owners)

    carriers = owners[:k]
    cleans = owners[k:]

    carrier_cap = depth_of(carriers)
    clean_cap = depth_of(cleans)

    print(f"max_inboxes_per_owner = {max_per_owner}")
    print(f"min owners needed: carrier={min_carrier_owners} clean={min_clean_owners}")
    print(f"carriers = {len(carriers)} (cap {carrier_cap} / need {req_carrier}, "
          f"min-owner-depth {min(depth[o] for o in carriers)})")
    print(f"clean    = {len(cleans)} (cap {clean_cap} / need {req_clean}, "
          f"min-owner-depth {min(depth[o] for o in cleans) if cleans else 0})")

    if len(carriers) < min_carrier_owners:
        raise SystemExit("not enough owners to host the attack set under the cap")
    if len(cleans) < min_clean_owners:
        raise SystemExit("not enough owners to host clean+benign under the cap")
    if carrier_cap < req_carrier:
        raise SystemExit(f"carrier capacity {carrier_cap} < need {req_carrier}")
    if clean_cap < req_clean:
        raise SystemExit(f"clean capacity {clean_cap} < need {req_clean}")

    group = {o: "carrier" for o in carriers}
    group.update({o: "clean" for o in cleans})

    rows = [
        {"owner": o, "group": group[o], "fake": E.fake_addr(o), "email_count": depth[o]}
        for o in sorted(group)
    ]
    write_jsonl(E.data_path("mailbox_split.jsonl"), rows)
    print(f"wrote {len(rows)} owners -> data/processed/email/mailbox_split.jsonl")


if __name__ == "__main__":
    main()
