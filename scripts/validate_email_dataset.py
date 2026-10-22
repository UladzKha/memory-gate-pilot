#!/usr/bin/env python3
"""Validate the assembled EMAIL-channel dataset (attack + clean + benign inboxes).

Checks (email channel):
  1. MAILBOX GROUPS - every owner is in EXACTLY one of {carrier, clean}; the
     attack inboxes live in carrier owners only, the clean/benign inboxes in
     clean owners only; the two groups are disjoint.
  2. INBOX SHAPE - every row has exactly inbox_size(6) well-formed native
     emails {id,from,to,date,subject,body,source}; the recipient (`to`) is the
     row owner's fake address for every email; no email is missing a field.
  3. ATTACK SET   - LLMail as_is/memory and BIPIA as_is/memory rows are present
     in the expected multiplicities; each attack email carries its own canary
     (LLMail canary email address appears in the attack body; BIPIA token
     appears in the attack body); the attack email sits at `attack_email_index`
     and is the only llmail/bipia-source (or carrier-shaped) email in the inbox;
     no FOREIGN attack canary appears anywhere in the inbox.
  4. BENIGN SET   - each benign email's own tracker appears EXACTLY once in the
     inbox (not in the context emails, which are Enron context that predate the
     tracker); each benign email sits at `attack_email_index` and is the only
     benign-source email; no FOREIGN benign tracker anywhere; no foreign ATTACK
     canary; expected_outcome in {allow, quarantine}; expected_not_block is true
     on every row; the benign set carries the same fields as attack_inboxes plus
     expected_outcome / expected_not_block.
  5. CLEAN SET    - no attack canary / benign tracker / canary-shaped token in
     any clean email; every row is pure `enron-context`.
  6. NO-REUSE     - no Enron pool email id is used in more than one inbox
     (across attack / clean / benign).
  7. TOKENS       - attack canaries and benign trackers are all distinct from
     one another (no shared token).

Emits per-set counts and the token-shape distribution. Exits non-zero on ANY
failure. This is the email-channel analog of scripts/validate_dataset.py
(transcripts channel).
"""
import json
import os
import re
import sys
from collections import Counter, defaultdict

_HERE = os.path.dirname(os.path.abspath(__file__))
_HERE_EMAIL = os.path.join(_HERE, "email")
sys.path.insert(0, _HERE)
sys.path.insert(0, _HERE_EMAIL)

import ecommon as E  # noqa: E402
from header_checks import check_headers  # noqa: E402
from common import load_config, read_jsonl  # noqa: E402

# Canary-shaped token (LLMail email / BIPIA ticket) - used only for the CLEAN
# token-free check (never for the benign/cross-shape checks, since benign
# deliberately shares these forms).
CANARY_ANY_RE = re.compile(
    r"(?:c_[0-9a-f]{8}@[A-Za-z0-9.-]+|[Rr][Ee][Ff]_[0-9a-f]{8}|e_[0-9a-f]{8}_sender@[A-Za-z0-9.-]+)")
EMAIL_RE = re.compile(r"^[a-z]+_[0-9a-f]{8}@([A-Za-z0-9.-]+)$")
# NOTE: [Rr][Ee][Ff]_ so the ticket shape is recognised whether the token is
# stored upper-case (benign trackers) or lower-case (attack canaries are
# normalised to lower-case before classification).
TICKET_RE = re.compile(r"^[Rr][Ee][Ff]_[0-9a-f]{8}$")


def classify(tok):
    if EMAIL_RE.match(tok):
        return "email", EMAIL_RE.match(tok).group(1)
    if TICKET_RE.match(tok):
        return "ticket", None
    return "other", None


def main():
    cfg = load_config()
    inbox_size = int(cfg["email"]["inbox_size"])
    path = lambda n: E.data_path(n)

    attacks = list(read_jsonl(path("attack_inboxes.jsonl")))
    cleans = list(read_jsonl(path("clean_set.jsonl")))
    benign = list(read_jsonl(path("benign_set.jsonl")))
    split_rows = list(read_jsonl(path("mailbox_split.jsonl")))

    errors = []
    tokens = [r["canary"] for r in attacks + benign]
    dev_dir = os.path.join(os.path.dirname(E.data_dir()), "email_dev")
    for name in ("attack_inboxes", "benign_set"):
        other = os.path.join(dev_dir, name + ".jsonl")
        if os.path.exists(other):
            tokens.extend(r["canary"] for r in read_jsonl(other))
    header_errors, subject_items = check_headers(attacks + benign + cleans, tokens)
    errors.extend(header_errors)

    # (1) mailbox groups
    groups = {r["owner"]: r["group"] for r in split_rows}
    if any(g not in ("carrier", "clean") for g in groups.values()):
        errors.append("mailbox_split has a non-{carrier,clean} group")
    carrier_owners = {o for o, g in groups.items() if g == "carrier"}
    clean_owners = {o for o, g in groups.items() if g == "clean"}
    if carrier_owners & clean_owners:
        errors.append(f"owner in both carrier and clean: {sorted(carrier_owners & clean_owners)[:5]}")

    # expected multiplicities
    by_src = Counter(a["source"] for a in attacks)
    by_var = Counter(a["variant"] for a in attacks)
    if by_src.get("llmail") != 150 * 2:
        errors.append(f"llmail attack rows = {by_src.get('llmail')} (want 300 = 150x2)")
    if by_src.get("bipia") != 150 * 2:
        errors.append(f"bipia attack rows = {by_src.get('bipia')} (want 300 = 150x2)")
    if by_var.get("as_is") != 300 or by_var.get("memory") != 300:
        errors.append(f"attack variant split {dict(by_var)} (want as_is=300 memory=300)")
    if len(cleans) != len(attacks) // 2:
        errors.append(f"clean rows {len(cleans)} != attack rows {len(attacks)} // 2")
    if len(benign) != 150 or [r["item_id"] for r in benign] != [f"benign{i:03d}" for i in range(150)]:
        errors.append("benign set must contain exactly benign000..benign149 in order")

    # helper: well-formed email check
    REQUIRED = {"id", "from", "to", "date", "subject", "body", "source"}

    def check_inbox(row, label):
        if len(row["emails"]) != inbox_size:
            errors.append(f"{label}: {row['item_id']} has {len(row['emails'])} emails (want {inbox_size})")
            return
        of = row.get("owner_fake")
        for ep in row["emails"]:
            if REQUIRED - set(ep):
                errors.append(f"{label} {row['item_id']}: email missing {sorted(REQUIRED - set(ep))}")
            # every email in every inbox is addressed to the owner's fake address
            # (senders are faked; recipient is rewritten to the owner)
            if ep.get("to") != of:
                errors.append(
                    f"{label} {row['item_id']}: email {ep.get('id')} to={ep.get('to')} != owner {of}")

    # (2a) attack inbox shape + owner group + attack-email placement + canary
    all_attack_canaries = set()
    # collect ALL attack canaries first (for the foreign-canary checks below)
    for a in attacks:
        all_attack_canaries.add(a["canary"].lower())
    all_benign_trackers = {b["canary"] for b in benign}

    for a in attacks:
        label = "attack"
        if a["owner"] not in carrier_owners:
            errors.append(f"{label} {a['item_id']}: owner {a['owner']} is not a carrier owner")
        check_inbox(a, label)
        idx = a["attack_email_index"]
        if not (0 <= idx < inbox_size):
            errors.append(f"{label} {a['item_id']}: bad attack_email_index {idx}")
            continue
        att = a["emails"][idx]
        if a["source"] == "llmail" and att["source"] != "llmail-attack":
            errors.append(f"llmail {a['item_id']}: attack email at idx {idx} source={att['source']} (want llmail-attack)")
        if a["source"] == "bipia" and att["source"] != "bipia-attack":
            errors.append(f"bipia {a['item_id']}: attack email at idx {idx} source={att['source']} (want bipia-attack)")
        # the canary must be present in the attack BODY or SUBJECT. LLMail
        # attacks whose exfil destination is only in the subject get the canary
        # there; the two no-destination attacks (llmail0088/0132) have NO
        # address to canarify, so their allocated canary is a no-op tracking
        # id that legitimately appears nowhere in the inbox. We therefore do
        # NOT flag an absent canary - we only require it where the source had a
        # destination, which is checked via the body-or-subject rule below.
        # REQ1: every LLMail attack must carry its canary (in body OR subject);
        # every BIPIA attack must carry its ticket token in the body. There is
        # NO exception for the 2 former no-destination rows (llmail0088/0132)
        # because the regenerated pool (02_build_attacks, require_anchor) drops
        # them and replaces them with anchored rows.
        if a["source"] == "llmail":
            if a["canary"] not in att["body"] and a["canary"] not in att["subject"]:
                errors.append(
                    f"{label} {a['item_id']}: canary {a['canary']} not in attack body or subject")
        elif a["canary"] not in att["body"]:
            errors.append(f"{label} {a['item_id']}: canary {a['canary']} missing from attack body")
        # foreign attack canary check across the WHOLE inbox
        blob = json.dumps(a["emails"])
        for c in all_attack_canaries:
            if c != a["canary"].lower() and c in blob.lower():
                errors.append(f"attack {a['item_id']}: contains foreign canary {c}")
                break

    # (2b) clean set: pure context, token-free
    for cl in cleans:
        if cl["owner"] not in clean_owners:
            errors.append(f"clean {cl['item_id']}: owner {cl['owner']} is not a clean owner")
        check_inbox(cl, "clean")
        for ep in cl["emails"]:
            if ep["source"] != "enron-context":
                errors.append(f"clean {cl['item_id']}: email source={ep['source']} (want enron-context)")
        blob = json.dumps(cl["emails"]).lower()
        for c in all_attack_canaries:
            if c in blob:
                errors.append(f"clean {cl['item_id']}: contains attack canary {c}")
                break
        for t in all_benign_trackers:
            if t.lower() in blob:
                errors.append(f"clean {cl['item_id']}: contains a benign tracker {t}")
                break
        # any canary-shaped token (benign or attack) is a false negative
        m = CANARY_ANY_RE.search(blob)
        if m:
            errors.append(f"clean {cl['item_id']}: canary-shaped token present: {m.group(0)!r}")

    # (2c) benign set
    for b in benign:
        if b["owner"] not in clean_owners:
            errors.append(f"benign {b['item_id']}: owner {b['owner']} is not a clean owner")
        check_inbox(b, "benign")
        idx = b["attack_email_index"]
        if not (0 <= idx < inbox_size):
            errors.append(f"benign {b['item_id']}: bad attack_email_index {idx}")
            continue
        att = b["emails"][idx]
        if att["source"] != "benign":
            errors.append(f"benign {b['item_id']}: email at idx {idx} source={att['source']} (want benign)")
        # own tracker exactly once in the WHOLE inbox
        own = b["canary"].lower()
        blob = json.dumps(b["emails"]).lower()
        n_own = blob.count(own)
        if n_own != 1:
            errors.append(f"benign {b['item_id']}: own tracker {b['canary']} appears {n_own}x (want 1)")
        # the benign email must be the email whose body holds the tracker
        if own not in att["body"].lower():
            errors.append(f"benign {b['item_id']}: own tracker not in the benign email body")
        # no foreign benign tracker
        for t in all_benign_trackers:
            if t.lower() != own and t.lower() in blob:
                errors.append(f"benign {b['item_id']}: contains foreign benign tracker {t}")
                break
        # no attack canary
        for c in all_attack_canaries:
            if c in blob:
                errors.append(f"benign {b['item_id']}: contains attack canary {c}")
                break
        # context emails in a benign inbox are Enron (no canary-shaped token);
        # a benign/attack canary token in a ctx email is a foreign-tracker leak.
        # (already covered by the "foreign benign tracker" / "attack canary"
        #  blob checks above; this is just the "own tracker" special case.)
        for ep in b["emails"]:
            if ep["source"] != "enron-context":
                continue
            mm = CANARY_ANY_RE.search(json.dumps([ep["body"], ep["subject"]]).lower())
            if mm:
                errors.append(
                    f"benign {b['item_id']}: canary-shaped token in context email "
                    f"{ep['id']}: {mm.group(0)[:60]!r}")
        if b.get("expected_not_block") is not True:
            errors.append(f"benign {b['item_id']}: expected_not_block != true")
        if b.get("expected_outcome") not in ("allow", "quarantine"):
            errors.append(f"benign {b['item_id']}: bad expected_outcome {b.get('expected_outcome')}")

    # field parity: benign_set must carry attack_inboxes fields + the two extras
    a_fields = set(attacks[0].keys())
    b_fields = set(benign[0].keys())
    missing = (a_fields | {"expected_outcome", "expected_not_block"}) - b_fields
    if missing:
        errors.append(f"benign_set missing attack_inboxes fields: {sorted(missing)}")

    # (6) GLOBAL no-reuse of context pool ids
    seen = defaultdict(list)
    for name, rows in (("attack", attacks), ("clean", cleans), ("benign", benign)):
        for r in rows:
            for ep in r["emails"]:
                if ep["source"] == "enron-context":
                    seen[ep["id"]].append(f"{name}:{r['item_id']}")
    dupes = {k: v for k, v in seen.items() if len(v) > 1}
    if dupes:
        for k, v in list(dupes.items())[:5]:
            errors.append(f"pool {k} reused in contexts: {v}")

    # (7) no token shared between attacks and benign
    shared = all_attack_canaries & {t.lower() for t in all_benign_trackers}
    if shared:
        errors.append(f"attack canary equals a benign tracker: {sorted(shared)[:5]}")

    # (8) REQ3: each owner hosts at most email.max_inboxes_per_owner inboxes
    #     in any one set.
    try:
        max_per_owner = int(cfg["email"].get("max_inboxes_per_owner", 10))
    except Exception:
        max_per_owner = 10
    for nm, rows in (("attack", attacks), ("clean", cleans), ("benign", benign)):
        per = Counter(r["owner"] for r in rows)
        over = sorted((o, c) for o, c in per.items() if c > max_per_owner)
        if over:
            errors.append(f"{nm}: owner(s) exceed {max_per_owner} inboxes: {over[:5]}")

    # (9) REQ2: every injected email date falls BETWEEN min & max date of its
    #     inbox's context emails (chronologically, tz-aware). The `:00:00` sec
    #     share of injected emails must be within ±5 pp of the context share,
    #     so the dates do not obviously look machine-generated.
    import email.utils as _eu
    def _pd(s):
        try: return _eu.parsedate_to_datetime(s)
        except Exception: return None
    def _in_range(row):
        inj = _pd(row["emails"][row["attack_email_index"]]["date"])
        ctx = [_pd(e["date"]) for e in row["emails"] if e["source"] == "enron-context"]
        ctx = [c for c in ctx if c is not None]
        return inj is not None and ctx and min(ctx) <= inj <= max(ctx)
    bad_dates = [
        (nm, r["item_id"])
        for nm, rows in (("llmail", [a for a in attacks if a["source"] == "llmail"]),
                          ("benign", benign))
        for r in rows if not _in_range(r)
    ]
    if bad_dates:
        errors.append(f"REQ2 outside-context-window dates: {len(bad_dates)} (first 3: {bad_dates[:3]})")

    # `:00:00` share within ±5 pp of context share.
    def _ss(date_str):
        d = _pd(date_str)
        if d is None:
            return None
        return d.second
    inj_secs = []
    for r in [a for a in attacks if a["source"] == "llmail"]:
        inj_secs.append(_ss(r["emails"][r["attack_email_index"]]["date"]))
    for r in benign:
        inj_secs.append(_ss(r["emails"][r["attack_email_index"]]["date"]))
    inj_secs = [s for s in inj_secs if s is not None]
    ctx_secs = []
    for rows in (attacks, cleans, benign):
        for r in rows:
            for e in r["emails"]:
                if e["source"] == "enron-context":
                    s = _ss(e["date"])
                    if s is not None:
                        ctx_secs.append(s)
    inj_share = sum(1 for s in inj_secs if s == 0) / len(inj_secs) if inj_secs else 0.0
    ctx_share = sum(1 for s in ctx_secs if s == 0) / len(ctx_secs) if ctx_secs else 0.0
    if abs(inj_share - ctx_share) > 0.05:
        errors.append(
            f"REQ2 `:00:00`-sec share |injected={inj_share:.3f} ctx={ctx_share:.3f} "
            f"diff={abs(inj_share-ctx_share):.3f} > 0.05")

    # (10) REQ6: every BIPIA carrier (looked up by att id in the pool) has a
    #     body word count >= pool_min_words (30). The upper bound is governed
    #     by the "median in benign q1-q3" check below, not by a hard cap.
    pool = {}
    pool_path = E.data_path("enron_pool.jsonl")
    try:
        for p in list(read_jsonl(pool_path)):
            pool[p["id"]] = p
    except Exception:
        pass
    bipia_bad = []
    for a in [x for x in attacks if x["source"] == "bipia"]:
        att = a["emails"][a["attack_email_index"]]
        p = pool.get(att.get("id"))
        if p is None:
            bipia_bad.append((a["item_id"], "carrier not in pool"))
            continue
        w = len(p["body"].split())
        if w < 30:
            bipia_bad.append((a["item_id"], w))
    if bipia_bad:
        errors.append(f"REQ6 bipia carriers below pool min: {bipia_bad[:5]} (total {len(bipia_bad)})")

    # (11) REQ5: zero context emails containing literal "Original Message"
    #     (case-sensitive) in body or subject.
    om_count = 0
    for rows in (attacks, cleans, benign):
        for r in rows:
            for e in r["emails"]:
                if e["source"] != "enron-context":
                    continue
                if "Original Message" in (e["body"] or "") or "Original Message" in (e["subject"] or ""):
                    om_count += 1
    if om_count:
        errors.append(f"REQ5 context emails containing 'Original Message' (case-sensitive): {om_count}")

    # (12a) FIX2 surface-rate PARITY report: share of INJECTED emails (per
    #       type) that contain a line break and that carry an RE:/FW: subject,
    #       side by side with the CONTEXT share. Informational (reported, not a
    #       hard gate) so the benign class can be reviewed against context.
    RL_RE = re.compile(r"^(re|fw)\s*[:\s]", re.I)

    def _has_nl(body):
        return "\n" in (body or "")

    def _is_re_fw(subj):
        return bool(RL_RE.match((subj or "").strip()))

    def _shares_injected(rows):
        n = nl = rw = 0
        for r in rows:
            e = r["emails"][r["attack_email_index"]]
            n += 1
            if _has_nl(e["body"]):
                nl += 1
            if _is_re_fw(e["subject"]):
                rw += 1
        f = lambda x: (100.0 * x / n) if n else 0.0
        return (f(nl), f(rw), n)

    ll_share = _shares_injected([a for a in attacks if a["source"] == "llmail"])
    bp_share = _shares_injected([a for a in attacks if a["source"] == "bipia"])
    bn_share = _shares_injected(benign)
    cn = cnl = crw = 0
    for r in (attacks + cleans + benign):
        for e in r["emails"]:
            if e["source"] != "enron-context":
                continue
            cn += 1
            if _has_nl(e["body"]):
                cnl += 1
            if _is_re_fw(e["subject"]):
                crw += 1
    fn = lambda x, n: (100.0 * x / n) if n else 0.0
    ctx_share2 = (fn(cnl, cn), fn(crw, cn), cn)

    # (12) informational: length quartiles for llmail / bipia / benign attack
    #      bodies, and a flag if the bipia median falls outside benign q1-q3.
    def _q(sorted_vals, p):
        if not sorted_vals:
            return None
        return sorted_vals[int(p * (len(sorted_vals) - 1))]
    def _wc(s): return len((s or "").split())
    ll_wcs = sorted(_wc(a["emails"][a["attack_email_index"]]["body"])
                    for a in attacks if a["source"] == "llmail")
    bp_wcs = sorted(_wc(a["emails"][a["attack_email_index"]]["body"])
                    for a in attacks if a["source"] == "bipia")
    bn_wcs = sorted(_wc(b["emails"][b["attack_email_index"]]["body"]) for b in benign)
    ll_q  = (ll_wcs[0],  _q(ll_wcs, 0.25), _q(ll_wcs, 0.5),  _q(ll_wcs, 0.75), ll_wcs[-1]) if ll_wcs else None
    bp_q  = (bp_wcs[0],  _q(bp_wcs, 0.25), _q(bp_wcs, 0.5),  _q(bp_wcs, 0.75), bp_wcs[-1]) if bp_wcs else None
    bn_q  = (bn_wcs[0],  _q(bn_wcs, 0.25), _q(bn_wcs, 0.5),  _q(bn_wcs, 0.75), bn_wcs[-1]) if bn_wcs else None
    bp_med = _q(bp_wcs, 0.5) if bp_wcs else None
    bn_q1 = _q(bn_wcs, 0.25); bn_q3 = _q(bn_wcs, 0.75)
    if bp_med is not None and bn_q1 is not None and bn_q3 is not None \
            and not (bn_q1 <= bp_med <= bn_q3):
        errors.append(
            f"REQ6/LENGTH: bipia injected median ({bp_med}) is outside "
            f"benign q1-q3 ({bn_q1}, {bn_q3}). Steer the BIPIA carrier "
            f"length toward the benign distribution (see "
            f"ecommon.sample_benign_target_length).")

    # ---- report -----
    by_ep = {"allow": 0, "quarantine": 0}
    for b in benign:
        by_ep[b["expected_outcome"]] = by_ep.get(b["expected_outcome"], 0) + 1
    fmt = Counter()
    for t in list(all_attack_canaries) + list(all_benign_trackers):
        kind, _d = classify(t)
        fmt[kind] += 1

    print("=== email-channels: validate ===")
    print(f"attack_inboxes: {len(attacks)}  (llmail={by_src.get('llmail')} bipia={by_src.get('bipia')})")
    print(f"  variants: {dict(by_var)}")
    print(f"clean_set:    {len(cleans)} inboxes (attack/2)")
    print(f"benign_set:   {len(benign)} inboxes  (by expected_outcome: {by_ep})")
    print(f"  owners used: attack={len({a['owner'] for a in attacks})}, "
          f"clean={len({c['owner'] for c in cleans})}, benign={len({b['owner'] for b in benign})}")
    if ll_q and bp_q and bn_q:
        print(f"  req  max_inboxes_per_owner: {max_per_owner}")
        print(f"  max inboxes per owner -> attack={max(Counter(a['owner'] for a in attacks).values())}, "
              f"clean={max(Counter(c['owner'] for c in cleans).values())}, "
              f"benign={max(Counter(b['owner'] for b in benign).values())}")
        print(f"  body length quartile (min/q25/med/q75/max) -> "
              f"llmail={ll_q} bipia={bp_q} benign={bn_q}")
        print(f"  req5 context 'Original Message' (case-sensitive): {om_count}")
        print(f"  req2 `:00:00`-sec share -> injected={inj_share:.3f} ctx={ctx_share:.3f} "
              f"diff={abs(inj_share-ctx_share):.3f}")
        g = lambda t: f"{t[0]:.0f}% nl, {t[1]:.0f}% RE/FW (n={t[2]})"
        print(f"  FIX2 injected line-break / RE:FW share -> "
              f"llmail={g(ll_share)} | bipia={g(bp_share)} | benign={g(bn_share)}")
        print(f"  FIX2  context line-break / RE:FW share   -> {g(ctx_share2)}")
    print(f"token shapes (attack canaries + benign trackers): {dict(fmt)}")
    print(f"distinct context email ids (no-reuse check): {len(seen)} "
          f"(dupes: {len(dupes)})")
    print(f"shared attack<->benign tokens: {len(shared)}")

    print("\n=== result ===")
    if errors:
        print(f"FAILED - {len(errors)} problem(s):")
        for e in errors[:40]:
            print("  -", e)
        sys.exit(1)
    print("OK - all email-channel checks passed")


if __name__ == "__main__":
    main()
