#!/usr/bin/env python3
"""Step 2: Collect attack items.

BIPIA: all strings from text_attack_train.json + text_attack_test.json with category.
LLMail-Inject: stream the (large) raw submissions, keep rows with
  objectives.exfil.sent == true AND objectives.exfil.destination == true,
  dedupe by body, drop bodies over max words, sample N seeded, stratified by scenario.

Writes: data/processed/attacks.jsonl
        ids are assigned in deterministic order here; canaries are added in step 4.
Idempotent: pure function of inputs + seed.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (decode_stray_escapes, load_config, make_rng, repo_root,
                    write_jsonl, word_count)


def collect_bipia(cfg, root):
    items = []
    for rel in cfg["attacks"]["bipia"]["files"]:
        with open(os.path.join(root, rel), encoding="utf-8") as f:
            data = json.load(f)
        for category in data:
            for text in data[category]:
                items.append({"source": "bipia", "category_or_scenario": category, "text": text})
    return items


def objectives_of(rec):
    obj = rec.get("objectives")
    if isinstance(obj, str):
        obj = json.loads(obj)
    return obj or {}


def collect_llmail(cfg, root):
    max_words = int(cfg["attacks"]["llmail"].get("max_body_words", 300))
    # Reserve wrapper words for the "Subject: ... Body: ..." framing + the
    # memory-template overhead so BOTH the as_is and memory variants stay
    # under the 300-word cap.
    llmail_cfg = cfg["attacks"]["llmail"]
    reserve = int(llmail_cfg.get("max_body_reserve",
                                 cfg["canary"].get("llmail_wrapped_reserve", 12)))
    limit = max_words - reserve
    seen_bodies = set()
    pool = {}  # decoded body -> record (first occurrence wins, file order is stable)
    anchor = int(cfg["attacks"]["llmail"].get("require_anchor", True)) and \
             cfg["canary"]["llmail_attacker_address"].lower()
    for rel in cfg["attacks"]["llmail"]["files"]:
        with open(os.path.join(root, rel), encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                obj = objectives_of(rec)
                if not (obj.get("exfil.sent") and obj.get("exfil.destination")):
                    continue
                # fix 8: decode literal \\uXXXX (double-encoded in the raw
                # data) to the real characters. Single-backslash escapes were
                # already decoded by json.loads; only literal leftover
                # sequences are handled here.
                subject = decode_stray_escapes(rec.get("subject") or "")
                body = decode_stray_escapes(rec.get("body") or "")
                if body in seen_bodies:
                    continue
                # fix 7: cap on subject + body combined (after the template
                # wrapper), not body only.
                if (word_count(subject) + word_count(body)) > limit:
                    continue
                # REQ1: only keep rows that actually carry the attacker address
                # (the exfil destination). Those with no destination have no
                # address to canarify, so they are dropped here and replaced by
                # anchored rows via the seeded stratified sample.
                if anchor and anchor not in (body + " " + subject).lower():
                    continue
                seen_bodies.add(body)
                pool[body] = {
                    "source": "llmail",
                    "category_or_scenario": rec.get("scenario"),
                    "subject": subject,
                    "body": body,
                    "team_id": rec.get("team_id"),
                }
    records = list(pool.values())

    # Stratified seeded sample: proportional shares per scenario via largest
    # remainder, then seeded shuffle within each stratum.
    want = int(cfg["attacks"]["llmail"]["count"])
    rng = make_rng(cfg, "llmail_dedup")
    rng.shuffle(records)
    by_scen = {}
    for r in records:
        by_scen.setdefault(r["category_or_scenario"], []).append(r)
    shares = proportional_share(want, {k: len(v) for k, v in by_scen.items()})
    taken = []
    for scen in sorted(by_scen):
        group = by_scen[scen]
        k = min(shares.get(scen, 0), len(group))
        sel = rng.sample(group, k) if k < len(group) else list(group)
        taken.extend(sel)
    if len(taken) < want:
        leftovers = [r for r in records if r not in taken]
        rng.shuffle(leftovers)
        taken.extend(leftovers[: want - len(taken)])
    taken.sort(key=lambda r: (r["category_or_scenario"], r["body"]))
    out = []
    for i, r in enumerate(taken):
        out.append({
            "attack_id": f"llmail{i:04d}",
            "source": "llmail",
            "category_or_scenario": r["category_or_scenario"],
            "subject": r["subject"],
            "body": r["body"],
            "team_id": r["team_id"],
            "text": r["body"],
        })
    return out, {"unique_bodies_pool": len(pool), "scenarios": {k: len(v) for k, v in sorted(by_scen.items())}}


def proportional_share(total, sizes):
    total_size = sum(sizes.values()) or 1
    exact = {k: total * s / total_size for k, s in sizes.items()}
    base = {k: int(v) for k, v in exact.items()}
    remain = total - sum(base.values())
    for k, _ in sorted(exact.items(), key=lambda kv: (-(exact[kv[0]] - base[kv[0]]), kv[0])):
        if remain <= 0:
            break
        base[k] += 1
        remain -= 1
    return base


def main():
    cfg = load_config()
    root = repo_root()
    bipia = collect_bipia(cfg, root)
    want = int(cfg["attacks"]["bipia"]["count"])
    for i, b in enumerate(bipia[:want]):
        b["attack_id"] = f"bipia{i:04d}"
    bipia = bipia[:want]

    llmail, llmail_stats = collect_llmail(cfg, root)

    all_items = bipia + llmail
    out = os.path.join(root, cfg["paths"]["processed_root"], "attacks.jsonl")
    write_jsonl(out, all_items)
    with open(os.path.join(root, cfg["paths"]["processed_root"], "attacks_stats.json"), "w", encoding="utf-8", newline="") as f:
        f.write(json.dumps({"bipia": len(bipia), "llmail": len(llmail), "llmail_stats": llmail_stats},
                           ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    print(f"bipia={len(bipia)} llmail={len(llmail)} -> {out}")
    print(f"llmail_stats: {llmail_stats}")


if __name__ == "__main__":
    main()
