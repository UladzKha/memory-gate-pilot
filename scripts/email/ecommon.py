"""Shared helpers for the email-channel build (native From/To/Date/Subject/Body items)."""
import hashlib
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import (  # noqa: E402
    HEX,
    make_rng,
    new_hex8,
    repo_root,
    read_jsonl,
    stable_dump,
    word_count,
    write_jsonl,
)


def data_dir():
    return os.path.join(repo_root(), "data", "processed", "email")


def data_path(name):
    return os.path.join(data_dir(), name)


def write(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(stable_dump(obj) + "\n")


# --- deterministic identity mapping (channel-agnostic) ------------------------
def fake_addr(addr):
    """Stable fake recipient/sender for a real Enron address (privacy)."""
    h = hashlib.sha1(str(addr).lower().encode("utf-8")).hexdigest()[:8]
    return f"p_{h}@example.org"


def relay_address(hex8):
    return f"c_{hex8}@relay.example.net"


def bipia_token(hex8):
    return f"REF_{hex8}"


# --- surface-form detectors (shared by benign_texts.py + check_benign.py) ------
# Both the LLMail attacks and the benign emails are measured with EXACTLY
# these, so the two reported rates are directly comparable (feedback #3 / #5).

_GREETINGS = ("hi", "hello", "hey", "dear", "good morning",
              "good afternoon", "good evening", "good day", "morning",
              "greetings", "how are you")
# Trailing valediction (a "sign-off" closing phrase). Order matters only in
# the alternation below (longest phrasal forms first); matched word-bounded
# and case-insensitively somewhere in the body, so multi-paragraph letters and
# single-paragraph notes are both caught.
_SIGNOFF_VALE_RE = re.compile(
    r"\b(best\s+regards|warm\s+regards|with\s+best\s+regards|kind\s+regards|"
    r"regards|best\s+wishes|best\s+of\s+your\s+success|best\b|sincerely|"
    r"yours\s+sincerely|yours\s+truly|faithfully|cordially|respectfully|"
    r"cheers|hugs|thank\s+you|thanks\s+a\s+lot|thanks|thnx|gratefully|"
    r"grateful|yours|lovingly|see\s+you\s+soon|talk\s+soon|talk\s+later|"
    r"take\s+care|warmest)\b", re.I)
# Signature-like words allowed to TRAIL a valediction (surname, initial, or a
# short professional title). Anything else (a sentence, a URL, a quoted token)
# disqualifies it.
_STOP = {"i", "a", "an", "the", "in", "to", "and", "or", "of", "is", "be",
         "by", "for", "we", "you", "they", "it", "this", "that", "with",
         "from", "your", "my", "our", "their", "will", "can", "have", "has",
         "had", "been", "are", "was", "were", "do", "does", "did", "please",
         "all", "not", "no", "so", "as", "at", "on", "off", "out", "up",
         "if", "when", "who", "which", "where", "me", "us", "them",
         "him", "her"}


def has_greeting(body):
    """True if the body OPENS on a greeting (Hi / Hello / Hey / Dear / Good
    day / Morning ...), matched case-insensitively and word-bounded."""
    import re as _re
    b = (body or "").strip()
    if not b:
        return False
    m = _re.match(
        r"^(hi|hello|hey|dear|good\s+(morning|afternoon|evening|day)|"
        r"morning|greetings|how\s+are\s+you)\b", b, flags=_re.I)
    return bool(m)


def _sig_trailing(text):
    """True if the text after a valediction is a plausible signature: blank, or
    only initials / capitalised name tokens / short titles. Reject URLs, emails
    and any lowercased sentence word so mid-body prose and attack payloads do
    not trigger it."""
    text = (text or "").strip()
    if not text:
        return True
    for tok in re.findall(r"[A-Za-z0-9\.\-]+", text):
        if "@" in tok or "http" in tok.lower():
            return False
        if re.fullmatch(r"[A-Za-z]\.?", tok):
            continue
        if tok.lower() in _STOP:
            continue
        if tok[0].isupper():
            continue
        return False
    return True


def has_signoff(body):
    """True if the body ENDS on a sign-off: a trailing valediction (regards /
    thanks / sincerely / cheers / best / talk soon / warmest ...) followed by a
    plausible signature (initials + name (+ title)), or a phone extension.

    This inspects the END of the message rather than only the final line, so
    single-paragraph notes that embed a closing valediction ("... Best, J. Doe")
    are caught exactly like multi-paragraph letters. A valediction mid-sentence
    ("thanks in advance for ...") does NOT trigger it because its tail is prose,
    not a signature.
    """
    b = (body or "").strip()
    if not b:
        return False
    # latest valediction whose tail looks like a signature wins
    for m in reversed(list(_SIGNOFF_VALE_RE.finditer(b))):
        if _sig_trailing(b[m.end():]):
            return True
    # a bare phone-extension signature with no valediction
    if re.search(r"\bext(?:ension)?\s*\d{2,4}\s*$", b, re.I) or \
        re.search(r"\bx\s+\d{2,3}\s*$", b, re.I):
        return True
    return False


# --- benign render-time formatting (FIX2) -------------------------------------
# The frozen benign bodies are single flat paragraphs; real email context uses
# line breaks (96%) and RE:/FW: subjects (~22%). These helpers reformat a frozen
# body at RENDER time (words are NOT changed: only paragraph breaks are inserted
# and a greeting / sign-off, if present, is lifted onto its own line; ~20% get an
# "RE: " subject prefix). Everything is seeded by item id, so the output is
# byte-identical across runs.
_GREET_LINE_RE = re.compile(
    r"^\s*(?:hi|hello|hey|dear|good\s+(?:morning|afternoon|evening|day)|"
    r"morning|greetings|how\s+are\s+you)"
    r"(?:\s+[A-Za-z]+){0,2}\s*([,.!\?]?)",
    re.I)


def _sign_off_start(body):
    """Index where a trailing valediction+signature begins, or None.

    Mirrors ``has_signoff``: the LAST valediction whose tail looks like a
    signature wins, so a mid-body "thanks in advance / best practice" does not
    trigger it."""
    b = (body or "").strip()
    if not b:
        return None
    for m in reversed(list(_SIGNOFF_VALE_RE.finditer(b))):
        if _sig_trailing(b[m.end():]):
            return m.start()
    return None


def _split_sentences(core):
    parts, pos = [], 0
    for m in re.finditer(r"[.!?](\s+)", core):
        if m.end() < len(core) and core[m.end()].isupper():
            parts.append(core[pos:m.start() + 1])
            pos = m.end()
    if pos < len(core):
        parts.append(core[pos:])
    return [p.strip() for p in parts if p.strip()]


def reformat_benign_body(body, cfg, salt):
    """Reformat a flat benign body into 1-4 paragraphs (words unchanged)."""
    b = (body or "").strip()
    if not b:
        return body
    m = _GREET_LINE_RE.match(b)
    if m and m.group(0).strip():
        greet = m.group(0).strip()
        core = b[m.end():].strip()
    else:
        greet = None
        core = b
    so_start = _sign_off_start(core)
    if so_start is not None:
        so = core[so_start:].strip()
        core = core[:so_start].strip()
    else:
        so = None
    core = core.strip()
    # budget: total lines (greeting, sign-off, core paragraphs) must be <= 4.
    budget = 4
    if greet:
        budget -= 1
    if so:
        budget -= 1
    budget = max(1, budget)
    if not core:
        paras = []
    else:
        sents = _split_sentences(core)
        rng = make_rng(cfg, "benign.paras." + salt)
        n = len(sents)
        k = rng.randint(1, max(1, min(budget, n)))
        if n <= 1 or k <= 1:
            paras = [core]
        else:
            cuts = sorted(rng.sample(range(1, n), k - 1))
            paras, start = [], 0
            for c in cuts:
                paras.append(" ".join(sents[start:c]))
                start = c
            paras.append(" ".join(sents[start:]))
    lines = ([greet] if greet else []) + paras + ([so] if so else [])
    return "\n\n".join([x for x in lines if x])


def benign_subject(subject, cfg, salt):
    """Prefix 'RE: ' to ~20% of benign subjects (seeded, per item)."""
    rng = make_rng(cfg, "benign.re." + salt)
    if rng.random() < 0.20:
        return "RE: " + (subject or "").strip()
    return subject


# --- source data --------------------------------------------------------------
def load_pool():
    return list(read_jsonl(data_path("enron_pool.jsonl")))


def load_attacks():
    """Attack pool (150 llmail + 150 bipia). Lives in the email dir as attacks_pool.jsonl."""
    p = data_path("attacks_pool.jsonl")
    if not os.path.exists(p):
        # fall back to the transcripts pool if not copied yet
        p = os.path.join(repo_root(), "data", "processed", "transcripts_v0", "attacks.jsonl")
    return list(read_jsonl(p))


def llmail_hex8(cfg, seed):
    """Per-item deterministic 8-hex canary id (order-independent)."""
    return new_hex8(make_rng(cfg, "canary." + seed + ".llmail"))


def bipia_hex8(cfg, seed):
    return new_hex8(make_rng(cfg, "canary." + seed + ".bipia"))


def llmail_sender(cfg, item_id):
    """Deterministic sender, derived independently of all canary seeds."""
    hex8 = new_hex8(make_rng(cfg, "sender.llmail." + item_id))
    return f"p_{hex8}@example.org"


def max_inboxes_per_owner(cfg):
    """REQ3: max inboxes a single owner may host in any one set."""
    return int(cfg["email"].get("max_inboxes_per_owner", 10))


def sample_benign_target_length(cfg, salt):
    """Sample a target injected-email body length from the FROZEN benign class.

    Reads the 60 approved benign bodies (``benign_emails.jsonl``) and returns
    a deterministic choice from their word-count distribution, keyed on
    ``cfg.seed:salt``. Used to steer the BIPIA carrier length toward the
    benign length distribution so the two classes are indistinguishable by
    length alone.
    """
    import random

    from common import read_jsonl

    benign = list(read_jsonl(data_path("benign_emails.jsonl")))
    if not benign:
        raise SystemExit("benign_emails.jsonl is missing or empty")
    lengths = [word_count(b["body"]) for b in benign]
    rng = random.Random(f"{cfg['seed']}:{salt}")
    return rng.choice(lengths)


def _parse_date(date_str):
    """Best-effort parse of an RFC822 date into a tz-aware datetime (UTC if naive)."""
    import email.utils
    from datetime import datetime, timezone
    try:
        dt = email.utils.parsedate_to_datetime(date_str)
    except Exception:
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _fmt_rfc822(dt, tzname, offstr):
    # RFC822 / Enron style: "Wed, 15 Nov 2001 09:00:00 -0800 (PST)"
    # %a = weekday name (Sun..Sat), %b = month abbr (Jan..Dec). Day is
    # space-padded to 2 chars to match the source format.
    return (f"{dt.strftime('%a')}, {dt.day:2d} {dt.strftime('%b')} {dt.year} "
            f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} {offstr} ({tzname})")


def _offset_parts(dt):
    off = dt.utcoffset()
    if off is None:
        return "-0000", "UTC"
    total = int(off.total_seconds())
    sign = "-" if total < 0 else "+"
    total = abs(total)
    offstr = f"{sign}{total // 3600:02d}{(total % 3600) // 60:02d}"
    tzname = dt.tzname() or "TZ"
    return offstr, tzname


def seeded_injected_date(cfg, salt, other_dates):
    """Deterministic RFC822 date for an injected email, constrained to fall
    BETWEEN the min and max date of the inbox's other (context) emails, with a
    seeded hour/minute/second. The offset + tz name come from the median context
    date so the stamp is consistent with the inbox.

    Implementation: one seeded uniform draw in ``[lo, hi]`` (seconds), then
    format in the *median* context tz (so the offset + tz-name look like the
    rest of the inbox). No wall clock: everything derives from cfg seed + salt,
    so repeated runs are byte-identical.
    """
    import datetime as _dt

    parsed = [d for d in (_parse_date(x) for x in other_dates) if d is not None]
    if not parsed:
        return "Wed, 15 Nov 2001 09:00:00 -0800 (PST)"
    lo, hi = min(parsed), max(parsed)
    med = sorted(parsed)[len(parsed) // 2]
    offstr, tzname = _offset_parts(med)

    rng = make_rng(cfg, "injecteddate." + salt)
    span_seconds = int((hi - lo).total_seconds())
    offset = rng.randint(0, max(span_seconds, 0))
    # A single instant uniformly in [lo, hi], then rendered in the median tz
    # (matches the inbox's tz convention).
    stamp = (lo + _dt.timedelta(seconds=offset)).astimezone(med.tzinfo)
    return _fmt_rfc822(stamp, tzname, offstr)


class Canary:
    """Deterministic, order-independent per-item canary derivation (no shared state).

    Every value for an item is derived from a per-item seed string, so results
    are identical regardless of the order items are processed.
    """

    def __init__(self, cfg):
        self.cfg = cfg
        self.domain = cfg["canary"]["llmail_relay_domain"]
        self.attacker = cfg["canary"]["llmail_attacker_address"]
        self.templates = cfg["templates"]["memory"]
        self.ticket_patterns = cfg["canary"]["ticket_patterns"]

    def llmail(self, body, seed, subject=""):
        """Render an LLMail body AND subject: replace EVERY attacker address
        (the exfil destination) with a fresh canary.

        Returns (canary, replaced_body, replaced_subject, hex8). Attacks whose
        destination lives only in the subject (e.g. 'from: contact@contact.com')
        get the canary in the subject; attacks with no destination at all (no
        address in body or subject) leave the canary unplaced — a no-op tracking
        id that the gate detects by other means."""
        import re as _re

        hex8 = llmail_hex8(self.cfg, seed)
        canary = f"c_{hex8}@{self.domain}"
        pat = _re.compile(_re.escape(self.attacker), _re.I)
        replaced = pat.sub(canary, body or "")
        replaced_subject = pat.sub(canary, subject or "")
        return canary, replaced, replaced_subject, hex8

    def memory_wrap(self, base, seed):
        """Wrap a rendered payload in a memory template (memory variant)."""
        r = make_rng(self.cfg, "canary." + seed + ".wrap")
        return r.choice(self.templates).format(attack=base)

    def bipia(self, text, seed):
        """Weave a BIPIA payload into a ticket pattern with a fresh unique token.

        Returns (token, rendered, hex8)."""
        hex8 = bipia_hex8(self.cfg, seed)
        token = bipia_token(hex8)
        r = make_rng(self.cfg, "canary." + seed + ".pat")
        pat = r.choice(self.ticket_patterns)
        return token, pat.format(a=text, tok=token), hex8
