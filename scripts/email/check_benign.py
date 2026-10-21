#!/usr/bin/env python3
"""Step 3: gate on the authored benign DRAFT (email channel).

Re-checks every authored benign row in data/processed/email/benign_emails_DRAFT.jsonl
(built across all batches of benign_texts.py) against the LLMail selected set:

  PER-ROW checks (every row must pass):
    * tracker appears EXACTLY once
    * no forbidden meta words
    * body word count within +/-15% of the spec's target_words
    * if the spec has a memory_template, body begins with it EXACTLY
    * expected_not_block == true, expected_outcome in {allow, quarantine}

  NEAR-DUPLICATE check (every pair of rows must pass):
    * no two emails share 12 or more word trigrams

  RATE checks (benign vs LLMail, shared detectors from ecommon):
    * SIGN-OFF rate : benign within 5 percentage points of LLMail
    * GREETING  rate: benign within 10 percentage points of LLMail

Prints both rates for each set. Exits non-zero on ANY per-row failure, a
near-duplicate pair, or if a rate is out of range from LLMail.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)                      # scripts/email/ (ecommon.py)
sys.path.insert(0, os.path.dirname(_HERE))     # scripts/ (common.py)

import re  # noqa: E402
from common import word_count  # noqa: E402
import ecommon as E  # noqa: E402

FORBIDDEN_RE = None  # lazy: reuse benign_texts' to stay in sync


def _forbidden_re():
    global FORBIDDEN_RE
    if FORBIDDEN_RE is None:
        FORBIDDEN_RE = re.compile(
            r"\b(attack|injection|benign|test|canary|tracker)\b", flags=re.I)
    return FORBIDDEN_RE


_WORD_TRIGRAMS = re.compile(r"[A-Za-z']+")


def word_trigrams(body):
    ws = _WORD_TRIGRAMS.findall((body or "").lower())
    return {tuple(ws[i:i + 3]) for i in range(len(ws) - 2)}


def _shared_trigram_pairs(rows):
    """Return pairs of emails sharing >=12 word trigrams (near-duplicates)."""
    trgs = {r["id"]: word_trigrams(r.get("body", "")) for r in rows}
    return sorted(
        (len(trgs[a] & trgs[b]), a, b)
        for a in trgs for b in trgs
        if a < b and len(trgs[a] & trgs[b]) >= 12)


def pct(n, d):
    return (100.0 * n / d) if d else 0.0


def main():
    draft_path = E.data_path("benign_emails.jsonl")
    spec_path = E.data_path("benign_specs.jsonl")
    if not os.path.exists(draft_path):
        raise SystemExit(f"no benign set at {draft_path} (run benign_texts.py first)")

    specs = {r["id"]: r for r in E.read_jsonl(spec_path)}
    rows = list(E.read_jsonl(draft_path))

    errors = []
    # ---- per-row checks -------------------------------------------------------
    for r in rows:
        i = r["id"]
        body = r.get("body", "")
        spec = specs.get(i)
        if spec is None:
            errors.append(f"{i}: no matching spec row")
            continue
        tracker = spec["tracker"].lower()
        if body.lower().count(tracker) != 1:
            errors.append(f"{i}: tracker appears {body.lower().count(tracker)}x (want 1)")
        if _forbidden_re().search(body):
            errors.append(f"{i}: forbidden meta word present")
        wc = word_count(body)
        lo, hi = 0.85 * spec["target_words"], 1.15 * spec["target_words"]
        if not (lo <= wc <= hi):
            errors.append(f"{i}: {wc} words outside [{lo:.0f},{hi:.0f}]")
        if spec.get("memory_template"):
            prefix = spec["memory_template"].split("{attack}")[0]
            if not body.startswith(prefix):
                errors.append(f"{i}: body does not start with memory_template verbatim")
        if r.get("expected_not_block") is not True:
            errors.append(f"{i}: expected_not_block != true")
        if r.get("expected_outcome") not in ("allow", "quarantine"):
            errors.append(f"{i}: bad expected_outcome: {r.get('expected_outcome')}")
        # flag "relay" in prose (i.e. not part of the tracker domain)
        import re as _re
        _cleaned = body.lower().replace(spec["tracker"].lower(), "")
        m = _re.search(r"\brelay(s)?\b", _cleaned)
        if m:
            _s, _e = max(0, m.start() - 25), min(len(_cleaned), m.end() + 15)
            _ctx = _cleaned[_s:_e].replace("\n", " ")
            errors.append(f'{i}: word "relay" in prose: ...{_ctx}...')

    # ---- near-duplicate check (word trigrams) -------------------------------
    dup_pairs = _shared_trigram_pairs(rows)
    for n, a, b in dup_pairs:
        errors.append(f"{a} & {b} share {n} word trigrams (>=12; near-duplicate)")

    # ---- rate checks (shared detectors) --------------------------------------
    llmail = [a for a in E.load_attacks() if a.get("source") == "llmail"]
    n_bn = len(rows)
    bn_sig = [r for r in rows if E.has_signoff(r.get("body", ""))]
    bn_gre = [r for r in rows if E.has_greeting(r.get("body", ""))]
    ll_sig = [a for a in llmail if E.has_signoff(a.get("body", ""))]
    ll_gre = [a for a in llmail if E.has_greeting(a.get("body", ""))]

    print("=== benign DRAFT: per-row + surface-rate gate (step 3) ===")
    print(f"rows: {n_bn}   LLMail selected set: {len(llmail)}\n")
    print("PER-ROW:")
    for e in errors:
        print("  -", e)
    if not errors:
        print("  all rows: tracker x1, no forbidden words, word band, "
              "memory prefix, labels OK")
    print("\nNEAR-DUPLICATE (>=12 shared word trigrams is a failure):")
    if dup_pairs:
        for n, a, b in dup_pairs:
            print(f"  - {a} & {b}: {n} shared trigrams")
    else:
        print("  no pairs share 12+ word trigrams")
    print("\nRATE (sign-off pass if within 5pp; greeting within 10pp):")
    print(f"  sign-off  LLMail: {len(ll_sig):>3} / {len(llmail):>3}  ({pct(len(ll_sig), len(llmail)):4.0f}%)   "
          f"benign: {len(bn_sig):>3} / {n_bn:>3}  ({pct(len(bn_sig), n_bn):4.0f}%)   "
          f"delta {abs(pct(len(bn_sig), n_bn) - pct(len(ll_sig), len(llmail))):.0f}pp")
    print(f"  greeting  LLMail: {len(ll_gre):>3} / {len(llmail):>3}  ({pct(len(ll_gre), len(llmail)):4.0f}%)   "
          f"benign: {len(bn_gre):>3} / {n_bn:>3}  ({pct(len(bn_gre), n_bn):4.0f}%)   "
          f"delta {abs(pct(len(bn_gre), n_bn) - pct(len(ll_gre), len(llmail))):.0f}pp")

    if abs(pct(len(bn_sig), n_bn) - pct(len(ll_sig), len(llmail))) > 5.0:
        errors.append("sign-off rate off LLMail by more than 5pp")
    if abs(pct(len(bn_gre), n_bn) - pct(len(ll_gre), len(llmail))) > 10.0:
        errors.append("greeting rate off LLMail by more than 10pp")

    print("\n=== result ===")
    if errors:
        print(f"FAILED - {len(errors)} problem(s)")
        sys.exit(1)
    print("OK - all per-row + surface-rate checks passed")


if __name__ == "__main__":
    main()
