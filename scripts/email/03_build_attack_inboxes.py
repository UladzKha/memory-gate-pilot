#!/usr/bin/env python3
"""Build the 600 attack inboxes (email channel).

For each distinct attack (150 LLMail + 150 BIPIA) x 2 variants (as_is, memory):

    attack inbox = 6 native {from,to,date,subject,body} emails
                  = 1 attack email at seeded pos 1..6, 5 other emails
    LLMail : attack email = the exfil email (subject + canaried body); 5 context
    BIPIA  : attack email = a context carrier whose body is woven with the token; 4 context

    context senders are faked; recipient rewritten to the item owner.
    GLOBAL no-reuse: a context email id is used at most once across the dataset
    (this file + clean/benign must be built in sequence and share that tracker).
"""
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ecommon as E
from common import load_config, make_rng, read_jsonl, write_jsonl


def load_mailbox_split():
    rows = list(read_jsonl(E.data_path("mailbox_split.jsonl")))
    return [r for r in rows if r["group"] == "carrier"], {r["owner"]: r for r in rows}


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


def insert_at(base, item, pos):
    base = list(base)
    base.insert(pos - 1, item)
    return base


def main():
    cfg = load_config()
    inbox_size = cfg["email"]["inbox_size"]  # 6
    carriers, owner_map = load_mailbox_split()
    carry_names = [c["owner"] for c in carriers]

    by_owner = defaultdict(list)
    for p in E.load_pool():
        if p["owner"] in owner_map:
            by_owner[p["owner"]].append(p)
    for o in by_owner:
        by_owner[o].sort(key=lambda r: r["id"])

    attacks = E.load_attacks()
    llmail = [a for a in attacks if a["source"] == "llmail"]
    bipia = [a for a in attacks if a["source"] == "bipia"]

    canary = E.Canary(cfg)
    usage = defaultdict(set)  # owner -> used pool ids
    inboxes = defaultdict(int)  # REQ3: owner -> inboxes already assigned (this set)
    max_per_owner = E.max_inboxes_per_owner(cfg)

    def pick_owner(need):
        cand = [o for o in carry_names
                if len(by_owner[o]) - len(usage[o]) >= need
                and inboxes[o] < max_per_owner]
        if not cand:
            raise SystemExit(f"no carrier owner has >= {need} unused ctx and < "
                             f"{max_per_owner} inboxes")
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

    # context-email sources that consume a pool id (plain ctx + woven BP carrier)
    CTX_SOURCES = ("enron-context", "bipia-attack")

    def emit(kind, attack, variant):
        item_id = f"{attack['attack_id']}_{variant}"
        owner = pick_owner(inbox_size)
        owner_fake = owner_map[owner]["fake"]
        seed = item_id

        if kind == "llmail":
            can, body, subject, hex8 = canary.llmail(
                attack["body"], seed, attack.get("subject") or "")
            ctx = take(owner, inbox_size - 1)
            # REQ2: stamp the injected email with a SEEDED date between the
            # min and max date of the inbox's other (context) emails.
            att_date = E.seeded_injected_date(
                cfg, "injecteddate.llmail." + item_id, [p["date"] for p in ctx])
            if variant == "memory":
                body = canary.memory_wrap(body, seed)
            att = {
                "id": attack["attack_id"],
                "from": E.llmail_sender(hex8),
                "to": owner_fake,
                "date": att_date,
                "subject": (subject or "Untitled").strip() or "Untitled",
                "body": body,
                "source": "llmail-attack",
            }
            base = [ctx_row(p, owner_fake) for p in ctx]
        else:
            # REQ6 (v2) + FIX1: the BIPIA carrier is a REAL Enron email whose
            # length is STEERED toward the benign-distribution target so the
            # two classes are indistinguishable by length. The ATTACK TEXT +
            # TICKET are the injected block (optionally memory-wrapped); they
            # are placed at a SEEDED position (start/middle/end) among the
            # carrier's paragraphs. The carrier body is otherwise left AS-IS.
            tok, rendered_plain, hex8 = canary.bipia(attack["text"], seed)
            picks = take(owner, inbox_size)
            wc = lambda p: len(p["body"].split())
            # carrier selection is done against the as-is injected block so
            # as_is and memory share the same carrier for a given attack.
            rendered_wc = len(rendered_plain.split())
            # seeded target from the FROZEN benign length distribution
            target = E.sample_benign_target_length(cfg, "bipia.target." + item_id)
            # pick the carrier whose (own length + injected-block length) is
            # closest to target; break ties by larger carrier length, then id
            def _score(p):
                return (abs(wc(p) + rendered_wc - target), -wc(p), p["id"])
            carrier = min(picks, key=_score)
            rest = [p for p in picks if p["id"] != carrier["id"]]
            if variant == "memory":
                block = canary.memory_wrap(rendered_plain, seed)
            else:
                block = rendered_plain
            place = make_rng(cfg, "bipia.place." + item_id).choice(
                ["start", "middle", "end"])
            paras = [x for x in carrier["body"].split("\n\n") if x.strip()]
            if place == "start":
                paras.insert(0, block)
            elif place == "middle":
                paras.insert(len(paras) // 2, block)
            else:
                paras.append(block)
            att = {
                "id": carrier["id"],
                "from": E.fake_addr(carrier["from"]),
                "to": owner_fake,
                "date": carrier["date"],
                "subject": carrier["subject"],
                "body": "\n\n".join(paras),
                "source": "bipia-attack",
            }
            base = [ctx_row(p, owner_fake) for p in rest]
            can = tok

        pos = make_rng(cfg, "pos." + item_id).randint(1, inbox_size)
        emails = insert_at(base, att, pos)

        return {
            "item_id": item_id,
            "attack_id": attack["attack_id"],
            "source": kind,
            "variant": variant,
            "carrier": kind == "bipia",
            "canary": can,
            "owner": owner,
            "owner_fake": owner_fake,
            "group": "carrier",
            "attack_email_index": pos - 1,
            "emails": emails,
        }

    items = []
    for a in llmail:
        for v in ("as_is", "memory"):
            items.append(("llmail", a, v))
    for a in bipia:
        for v in ("as_is", "memory"):
            items.append(("bipia", a, v))

    out = [emit(kind, attack, variant) for kind, attack, variant in items]
    out.sort(key=lambda r: r["item_id"])
    write_jsonl(E.data_path("attack_inboxes.jsonl"), out)

    # also record the used pool ids so clean/benign can enforce GLOBAL no-reuse
    used = {e["id"] for r in out for e in r["emails"] if e["source"] in CTX_SOURCES}
    with open(E.data_path("_used_ctx_ids.txt"), "w") as f:
        f.write("\n".join(sorted(used)) + "\n")

    print(f"attack_inboxes: {len(out)} items  "
          f"(llmail {sum(1 for r in out if r['source']=='llmail')}, "
          f"bipia {sum(1 for r in out if r['source']=='bipia')})")
    print(f"  distinct context pool ids consumed: {len(used)}")


if __name__ == "__main__":
    main()
