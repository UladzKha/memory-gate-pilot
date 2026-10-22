#!/usr/bin/env python3
"""Hard gate for dev/evaluation disjointness and evaluation-style email form."""

import json
import re
import sys
from collections import Counter
from datetime import timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / "email"))
from common import read_jsonl, word_count
from header_checks import check_headers

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "data/processed/email"
DEV = ROOT / "data/processed/email_dev"
REQUIRED = {"id", "from", "to", "date", "subject", "body", "source"}
TOKEN_RE = re.compile(r"(?:c_[0-9a-f]{8}@relay\.example\.net|REF_[0-9a-f]{8})", re.I)


def rows(directory):
    return {name: list(read_jsonl(directory / f"{name}.jsonl"))
            for name in ("attack_inboxes", "benign_set", "clean_set")}


def validate():
    ev, dev = rows(EVAL), rows(DEV)
    eval_pool = list(read_jsonl(EVAL / "attacks_pool.jsonl"))
    dev_pool = list(read_jsonl(DEV / "attacks_pool.jsonl"))
    errors = []
    eval_ll = {r["body"] for r in eval_pool if r["source"] == "llmail"}
    eval_teams = {r["team_id"] for r in eval_pool if r["source"] == "llmail"}
    eval_bp = {r["text"] for r in eval_pool if r["source"] == "bipia"}
    eval_benign = {r["body"].strip() for name in ("benign_emails.jsonl", "benign_emails_v2.jsonl")
                   for r in read_jsonl(EVAL / name)}
    dev_benign = {r["body"].strip() for r in read_jsonl(DEV / "benign_emails.jsonl")}
    dev_ll = [r for r in dev_pool if r["source"] == "llmail"]
    dev_ia = [r for r in dev_pool if r["source"] == "injecagent"]
    if len(dev_ll) != 100 or len(dev_ia) != 100:
        errors.append("attack pool must contain 100 LLMail and 100 InjecAgent cases")
    for label, overlap in (("LLMail body", {r["body"] for r in dev_ll} & eval_ll),
                           ("LLMail team_id", {r["team_id"] for r in dev_ll} & eval_teams),
                           ("benign source body", dev_benign & eval_benign),
                           ("InjecAgent/BIPIA text", {r["text"] for r in dev_ia} & eval_bp)):
        if overlap:
            errors.append(f"shared {label}: {list(overlap)[:3]}")
    eval_all = sum(ev.values(), [])
    dev_all = sum(dev.values(), [])
    header_errors, subject_items = check_headers(
        dev_all, [r["canary"] for r in dev["attack_inboxes"] + dev["benign_set"]
                 + ev["attack_inboxes"] + ev["benign_set"]])
    errors.extend(header_errors)
    enron_sources = {"enron-context", "bipia-attack", "injecagent-attack"}
    eval_ids = {e["id"] for r in eval_all for e in r["emails"] if e["source"] in enron_sources}
    for name in ("_used_ctx_ids.txt", "_clean_ctx_used.txt"):
        eval_ids.update((EVAL / name).read_text().splitlines())
    dev_ids = [e["id"] for r in dev_all for e in r["emails"] if e["source"] in enron_sources]
    overlap = set(dev_ids) & eval_ids
    if overlap:
        errors.append(f"shared Enron email IDs: {sorted(overlap)[:5]}")
    if len(dev_ids) != len(set(dev_ids)):
        errors.append(f"dev Enron email IDs reused internally: {len(dev_ids) - len(set(dev_ids))}")
    eval_tokens = {r["canary"].casefold() for r in ev["attack_inboxes"] + ev["benign_set"]}
    dev_tokens = [r["canary"].casefold() for r in dev["attack_inboxes"] + dev["benign_set"]]
    if eval_tokens & set(dev_tokens):
        errors.append(f"shared canary/tracker: {sorted(eval_tokens & set(dev_tokens))[:5]}")
    if len(dev_tokens) != len(set(dev_tokens)):
        errors.append("dev canary/tracker collision")
    if len({r["item_id"] for r in dev_all}) != len(dev_all):
        errors.append("duplicate item IDs")

    attack = dev["attack_inboxes"]
    benign = dev["benign_set"]
    clean = dev["clean_set"]
    by_source = Counter(r["source"] for r in attack)
    by_variant = Counter(r["variant"] for r in attack)
    if (len(attack), len(benign), len(clean)) != (400, 100, 100):
        errors.append(f"wrong set counts: {(len(attack), len(benign), len(clean))}")
    if by_source != {"llmail": 200, "injecagent": 200} or by_variant != {"as_is": 200, "memory": 200}:
        errors.append(f"wrong attack strata: {dict(by_source)} / {dict(by_variant)}")
    split = {r["owner"]: r["group"] for r in read_jsonl(DEV / "mailbox_split.jsonl")}
    injected_seconds = []
    context_seconds = []
    for set_name, group_rows in (("attack", attack), ("benign", benign), ("clean", clean)):
        per_owner = Counter(r["owner"] for r in group_rows)
        if per_owner and max(per_owner.values()) > 10:
            errors.append(f"{set_name} owner cap exceeded")
        for r in group_rows:
            expected_group = "carrier" if set_name == "attack" else "clean"
            if split.get(r["owner"]) != expected_group or r["group"] != expected_group:
                errors.append(f"{r['item_id']}: wrong owner group")
            emails = r["emails"]
            if len(emails) != 6:
                errors.append(f"{r['item_id']}: inbox has {len(emails)} emails")
                continue
            for ep in emails:
                if REQUIRED - ep.keys() or ep["to"] != r["owner_fake"]:
                    errors.append(f"{r['item_id']}: malformed email")
                if ep["source"] == "enron-context":
                    try:
                        context_seconds.append(parsedate_to_datetime(ep["date"]).second)
                    except Exception:
                        errors.append(f"{r['item_id']}: bad context date")
                    if "Original Message" in ep["body"] or "Original Message" in ep["subject"]:
                        errors.append(f"{r['item_id']}: quoted original message in context")
                    if TOKEN_RE.search(ep["body"] + ep["subject"]):
                        errors.append(f"{r['item_id']}: token in context")
            if set_name == "clean":
                if any(ep["source"] != "enron-context" for ep in emails):
                    errors.append(f"{r['item_id']}: non-context email in clean inbox")
                continue
            idx = r["attack_email_index"]
            if not 0 <= idx < 6:
                errors.append(f"{r['item_id']}: bad injected index")
                continue
            injected = emails[idx]
            expected_source = ("llmail-attack" if r["source"] == "llmail" else
                               "injecagent-attack" if r["source"] == "injecagent" else "benign")
            if injected["source"] != expected_source or sum(e["source"] != "enron-context" for e in emails) != 1:
                errors.append(f"{r['item_id']}: wrong injected email placement")
            blob = json.dumps(emails).casefold()
            own_count = blob.count(r["canary"].casefold())
            if (set_name == "benign" and own_count != 1) or (set_name == "attack" and own_count < 1):
                errors.append(f"{r['item_id']}: own token count {own_count} invalid")
            foreign = (set(dev_tokens) - {r["canary"].casefold()})
            if any(token in blob for token in foreign):
                errors.append(f"{r['item_id']}: foreign token")
            if r["canary"].casefold() not in (injected["body"] + injected["subject"]).casefold():
                errors.append(f"{r['item_id']}: own token absent from injected email")
            if r["source"] == "llmail" and word_count(injected["body"]) + word_count(injected["subject"]) > 300:
                errors.append(f"{r['item_id']}: LLMail injected email exceeds 300 words")
            if set_name == "benign" and (r["expected_not_block"] is not True or r["expected_outcome"] not in ("allow", "quarantine")):
                errors.append(f"{r['item_id']}: invalid benign outcome fields")
            if injected["source"] != "injecagent-attack":
                try:
                    date = parsedate_to_datetime(injected["date"]).astimezone(timezone.utc)
                    context_dates = [parsedate_to_datetime(ep["date"]).astimezone(timezone.utc)
                                     for ep in emails if ep["source"] == "enron-context"]
                    if not min(context_dates) <= date <= max(context_dates):
                        errors.append(f"{r['item_id']}: injected date outside context range")
                    injected_seconds.append(date.second)
                except Exception:
                    errors.append(f"{r['item_id']}: bad injected date")
    if injected_seconds and context_seconds:
        injected_zero = injected_seconds.count(0) / len(injected_seconds)
        context_zero = context_seconds.count(0) / len(context_seconds)
        if abs(injected_zero - context_zero) > 0.05:
            errors.append(f"injected :00:00 share differs from context by >5 pp ({injected_zero:.3f} vs {context_zero:.3f})")
    else:
        injected_zero = context_zero = 0
    def quartiles(values):
        values = sorted(values)
        return [values[int(p * (len(values) - 1))] for p in (0, .25, .5, .75, 1)]
    benign_lengths = quartiles([word_count(r["emails"][r["attack_email_index"]]["body"]) for r in benign])
    ia_lengths = quartiles([word_count(r["emails"][r["attack_email_index"]]["body"]) for r in attack if r["source"] == "injecagent"])
    if not benign_lengths[1] <= ia_lengths[2] <= benign_lengths[3]:
        errors.append(f"InjecAgent median {ia_lengths[2]} outside benign q1-q3 {benign_lengths[1]}-{benign_lengths[3]}")
    original_pool = {p["id"]: p for p in read_jsonl(EVAL / "enron_pool.jsonl")}
    for r in attack:
        if r["source"] == "injecagent":
            ep = r["emails"][r["attack_email_index"]]
            if ep["id"] not in original_pool or word_count(original_pool[ep["id"]]["body"]) < 30:
                errors.append(f"{r['item_id']}: invalid real Enron carrier")
    print(f"Dev counts: attacks={len(attack)} benign={len(benign)} clean={len(clean)}")
    print(f"Attack strata: {dict(by_source)} / {dict(by_variant)}")
    print("Cross-eval overlap: LLMail bodies=0, team_ids=0, benign bodies=0, "
          "InjecAgent/BIPIA text=0, Enron IDs=0, canaries/trackers=0")
    print(f"Dev Enron IDs: {len(dev_ids)} unique={len(set(dev_ids))}; owner cap: 10")
    print(f"Date :00:00 share: injected={injected_zero:.3f}, context={context_zero:.3f}")
    print(f"Body lengths min/q25/median/q75/max: InjecAgent={ia_lengths}, benign={benign_lengths}")
    if errors:
        print(f"FAILED ({len(errors)}):", *errors[:30], sep="\n - ")
        raise SystemExit(1)
    print("PASS: disjointness and evaluation-style form checks")


if __name__ == "__main__":
    validate()
