#!/usr/bin/env python3
"""Deterministically build email_dev from sources disjoint from dataset-v1."""

import json
import math
import re
import shutil
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / "email"))

import ecommon as E
from common import (decode_stray_escapes, load_config, make_rng, new_hex8,
                    read_jsonl, word_count, write_jsonl)

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "data/processed/email"
DEV = ROOT / "data/processed/email_dev"
INJEC = Path("/tmp/InjecAgent-dev")


def source_cases(cfg):
    snapshot = DEV / "injecagent_source_cases.jsonl"
    if snapshot.exists():
        rows = list(read_jsonl(snapshot))
    else:
        rows = []
        for kind in ("dh", "ds"):
            path = INJEC / "data" / f"test_cases_{kind}_base.json"
            for index, rec in enumerate(json.loads(path.read_text(encoding="utf-8"))):
                rows.append({"source_case_id": f"{kind}:{index:04d}",
                             "category_or_scenario": rec["Attack Type"],
                             "text": rec["Attacker Instruction"].strip()})
        write_jsonl(snapshot, rows)
    distinct = {}
    for row in rows:
        distinct.setdefault(row["text"], row)
    chosen = list(distinct.values())
    remaining = [row for row in rows if row["source_case_id"] not in
                 {r["source_case_id"] for r in chosen}]
    rng = make_rng(cfg, "dev.injecagent.sample")
    chosen.extend(rng.sample(remaining, 100 - len(chosen)))
    chosen.sort(key=lambda r: (r["category_or_scenario"], r["source_case_id"]))
    return [{**r, "attack_id": f"injecagent{i:04d}", "source": "injecagent"}
            for i, r in enumerate(chosen)]


def llmail_cases(cfg, eval_attacks):
    eval_teams = {r["team_id"] for r in eval_attacks if r["source"] == "llmail"}
    eval_bodies = {r["body"] for r in eval_attacks if r["source"] == "llmail"}
    pool = {}
    for phase in ("phase1", "phase2"):
        path = ROOT / f"data/raw/llmail-inject/data/raw_submissions_{phase}.jsonl"
        for rec in read_jsonl(path):
            obj = rec.get("objectives") or {}
            if isinstance(obj, str):
                obj = json.loads(obj)
            if not (obj.get("exfil.sent") and obj.get("exfil.destination")):
                continue
            team = rec.get("team_id")
            body = decode_stray_escapes(rec.get("body") or "")
            subject = decode_stray_escapes(rec.get("subject") or "")
            if (not team or team in eval_teams or body in eval_bodies or
                    word_count(body) + word_count(subject) > 288 or
                    "contact@contact.com" not in (body + " " + subject).lower()):
                continue
            pool.setdefault(body, {"body": body, "subject": subject, "team_id": team,
                                   "category_or_scenario": rec.get("scenario")})
    groups = defaultdict(list)
    for row in pool.values():
        groups[row["category_or_scenario"]].append(row)
    # Largest remainder preserves the eval pipeline's proportional stratification.
    exact = {k: 100 * len(v) / len(pool) for k, v in groups.items()}
    shares = {k: int(n) for k, n in exact.items()}
    for key in sorted(groups, key=lambda k: (-(exact[k] - shares[k]), k))[:100 - sum(shares.values())]:
        shares[key] += 1
    rng = make_rng(cfg, "dev.llmail.sample")
    chosen = []
    for group in sorted(groups):
        chosen.extend(rng.sample(groups[group], shares[group]))
    chosen.sort(key=lambda r: (r["category_or_scenario"], r["body"]))
    assert len(chosen) == 100
    return [{**r, "attack_id": f"devllmail{i:04d}", "source": "llmail", "text": r["body"]}
            for i, r in enumerate(chosen)]


def benign_cases(cfg):
    strings = json.loads((ROOT / "data/raw/llmail-inject/data/emails_for_fp_tests.json").read_text())
    parsed = []
    for index, value in enumerate(strings):
        match = re.match(r"(?is)^\s*Subject of the email:\s*(.*?)\s+Body:\s*(.+)\s*$", value)
        if match:
            parsed.append({"source_index": index, "subject": match.group(1).strip(),
                           "body": match.group(2).strip()})
    if len(parsed) < 100:
        raise RuntimeError(f"Only {len(parsed)} parseable LLMail false-positive emails")
    chosen = make_rng(cfg, "dev.benign.sample").sample(parsed, 100)
    return [{**row, "id": f"devbenign{i:03d}"} for i, row in enumerate(chosen)]


def build():
    cfg = load_config()
    cfg["seed"] = 45  # Separate deterministic dev namespace from dataset-v1.
    DEV.mkdir(parents=True, exist_ok=True)
    licence = DEV / "INJECAGENT_LICENCE.txt"
    if not licence.exists():
        shutil.copyfile(INJEC / "LICENCE", licence)
    if not licence.read_text().startswith("MIT License"):
        raise RuntimeError("InjecAgent license changed; stop")
    # The dev-v1 owner split was built against evaluation v1 (60 benign rows).
    # Preserve that frozen sampling frame when rebuilding after evaluation v2.
    eval_rows = [row for name in ("attack_inboxes", "benign_set", "clean_set")
                 for row in read_jsonl(EVAL / f"{name}.jsonl")
                 if name != "benign_set" or int(row["item_id"][6:]) < 60]
    eval_used = {ep["id"] for row in eval_rows for ep in row["emails"]
                 if ep["source"] in ("enron-context", "bipia-attack")}
    eval_attacks = list(read_jsonl(EVAL / "attacks_pool.jsonl"))
    llmail = llmail_cases(cfg, eval_attacks)
    injec = source_cases(cfg)
    benign = benign_cases(cfg)
    attacks = llmail + injec
    write_jsonl(DEV / "attacks_pool.jsonl", attacks)
    write_jsonl(DEV / "benign_emails.jsonl", benign)
    pool = [p for p in read_jsonl(EVAL / "enron_pool.jsonl") if p["id"] not in eval_used]
    depth = Counter(p["owner"] for p in pool)
    owners = sorted(depth, key=lambda o: (-depth[o], o))
    carrier_count = max(40, next(k for k in range(1, len(owners) + 1)
                                 if sum(depth[o] for o in owners[:k]) >= 2200))
    carrier_owners = set(owners[:carrier_count])
    clean_owners = set(owners[carrier_count:])
    if sum(depth[o] for o in clean_owners) < 1100 or len(clean_owners) < 20:
        raise RuntimeError("Insufficient clean-owner capacity")
    split = [{"owner": o, "group": "carrier" if o in carrier_owners else "clean",
              "fake": E.fake_addr(o), "email_count": depth[o]} for o in sorted(depth)]
    write_jsonl(DEV / "mailbox_split.jsonl", split)
    by_owner = defaultdict(list)
    for p in pool:
        by_owner[p["owner"]].append(p)
    for rows in by_owner.values():
        rows.sort(key=lambda p: p["id"])
    used = set()
    counts = {"attack": Counter(), "benign": Counter(), "clean": Counter()}
    max_per = E.max_inboxes_per_owner(cfg)

    def take(group, set_name, n, carrier_target=None, block_words=0):
        candidates = []
        for owner in (carrier_owners if group == "carrier" else clean_owners):
            available = [p for p in by_owner[owner] if p["id"] not in used]
            if counts[set_name][owner] < max_per and len(available) >= n:
                candidates.append((counts[set_name][owner], -len(available), owner, available))
        if not candidates:
            raise RuntimeError(f"No {group} owner can supply {n} emails for {set_name}")
        _, _, owner, available = min(candidates)
        if carrier_target is None:
            picks = available[:n]
        else:
            carrier = min(available, key=lambda p: (abs(word_count(p["body"]) + block_words - carrier_target),
                                                    -word_count(p["body"]), p["id"]))
            picks = [carrier] + [p for p in available if p["id"] != carrier["id"]][:n - 1]
        counts[set_name][owner] += 1
        used.update(p["id"] for p in picks)
        return owner, E.fake_addr(owner), picks

    def ctx(p, recipient):
        return {"id": p["id"], "from": E.fake_addr(p["from"]), "to": recipient,
                "date": p["date"], "subject": p["subject"], "body": p["body"],
                "source": "enron-context"}

    canary = E.Canary(cfg)
    attack_rows = []
    for attack in attacks:
        for variant in ("as_is", "memory"):
            item_id = f"{attack['attack_id']}_{variant}"
            is_ll = attack["source"] == "llmail"
            if is_ll:
                owner, recipient, picks = take("carrier", "attack", 5)
            else:
                token, block, _ = canary.bipia(attack["text"], item_id)
                target = word_count(benign[make_rng(cfg, "dev.target." + item_id).randrange(len(benign))]["body"]) + 18
                owner, recipient, picks = take("carrier", "attack", 6, target, word_count(block))
            if is_ll:
                token, body, subject, hex8 = canary.llmail(attack["body"], item_id, attack["subject"])
                if variant == "memory":
                    body = canary.memory_wrap(body, item_id)
                date = E.seeded_injected_date(cfg, "dev.llmail." + item_id, [p["date"] for p in picks])
                injected = {"id": attack["attack_id"], "from": E.llmail_sender(cfg, item_id),
                            "to": recipient, "date": date, "subject": subject or "Untitled",
                            "body": body, "source": "llmail-attack"}
                base = [ctx(p, recipient) for p in picks]
            else:
                carrier = picks[0]
                if variant == "memory":
                    block = canary.memory_wrap(block, item_id)
                paras = [x for x in carrier["body"].split("\n\n") if x.strip()]
                place = make_rng(cfg, "dev.place." + item_id).choice(("start", "middle", "end"))
                paras.insert(0 if place == "start" else len(paras) // 2 if place == "middle" else len(paras), block)
                injected = {**ctx(carrier, recipient), "body": "\n\n".join(paras), "source": "injecagent-attack"}
                base = [ctx(p, recipient) for p in picks if p["id"] != carrier["id"]]
            position = make_rng(cfg, "dev.pos." + item_id).randint(0, 5)
            base.insert(position, injected)
            attack_rows.append({"item_id": item_id, "attack_id": attack["attack_id"],
                                "source": attack["source"], "variant": variant,
                                "carrier": not is_ll, "canary": token, "owner": owner,
                                "owner_fake": recipient, "group": "carrier",
                                "attack_email_index": position, "emails": base})
    attack_rows.sort(key=lambda r: r["item_id"])
    write_jsonl(DEV / "attack_inboxes.jsonl", attack_rows)

    benign_rows = []
    for b in benign:
        item_id = b["id"]
        owner, recipient, picks = take("clean", "benign", 5)
        hex8 = new_hex8(make_rng(cfg, "dev.benign.token." + item_id))
        tracker = f"c_{hex8}@relay.example.net" if len(benign_rows) % 2 == 0 else f"REF_{hex8}"
        body = (b["body"].rstrip() + "\n\nPlease keep this reference for our next review; "
                f"it links the update to the current project record and helps the team find it later: {tracker}.")
        injected = {"id": item_id, "from": E.fake_addr("dev." + item_id),
                    "to": recipient, "date": E.seeded_injected_date(cfg, "dev.benign." + item_id,
                                                                  [p["date"] for p in picks]),
                    "subject": E.benign_subject(b["subject"], cfg, item_id),
                    "body": E.reformat_benign_body(body, cfg, item_id), "source": "benign"}
        emails = [ctx(p, recipient) for p in picks]
        position = make_rng(cfg, "dev.pos." + item_id).randint(0, 5)
        emails.insert(position, injected)
        benign_rows.append({"item_id": item_id, "attack_id": item_id, "source": "benign",
                            "variant": "as_is", "carrier": False, "canary": tracker,
                            "owner": owner, "owner_fake": recipient, "group": "clean",
                            "attack_email_index": position, "emails": emails,
                            "expected_outcome": "allow", "expected_not_block": True})
    write_jsonl(DEV / "benign_set.jsonl", benign_rows)

    clean_rows = []
    for i in range(100):
        owner, recipient, picks = take("clean", "clean", 6)
        clean_rows.append({"item_id": f"devclean{i:03d}", "owner": owner,
                           "owner_fake": recipient, "group": "clean", "source": "clean",
                           "emails": [ctx(p, recipient) for p in picks]})
    write_jsonl(DEV / "clean_set.jsonl", clean_rows)
    (DEV / "_used_ctx_ids.txt").write_text("\n".join(sorted({e["id"] for r in attack_rows for e in r["emails"] if e["source"] in ("enron-context", "injecagent-attack")})) + "\n")
    (DEV / "_clean_ctx_used.txt").write_text("\n".join(sorted({e["id"] for r in benign_rows + clean_rows for e in r["emails"] if e["source"] == "enron-context"})) + "\n")
    print(f"Built dev: {len(attack_rows)} attacks, {len(benign_rows)} benign, {len(clean_rows)} clean; {len(used)} Enron ids")
    print("InjecAgent types:", dict(Counter(r["category_or_scenario"] for r in injec)))
    print("InjecAgent unique instructions:", len({r["text"] for r in injec}))


if __name__ == "__main__":
    build()
