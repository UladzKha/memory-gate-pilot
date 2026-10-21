"""Parse the Enron maildir inbox folders into a clean, deduplicated global pool.

One record per in-range email:
  {id, owner, from, to, date, subject, body}

Rules:
  - owner      = mailbox directory name (the recipient / inbox owner)
  - from/to    = raw RFC822 header values (folded headers joined)
  - strip      : quoted-reply lines (leading '>') and everything from the
                 first '-----Original Message-----' marker; drop '<... File ...>'
                 attachment placeholders and their empty wrappers;
                 drop if body ends up empty after stripping.
  - keep       : word count within [min_words, max_words]; drop attachment-only
                 (no prose left).
  - dedupe     : global (cross-owner) uniqueness by sha1(from|date|subject|body).
  - order      : deterministic (owner asc, then source path asc).
  - encodings  : UTF-8 strict, latin-1 fallback; stray \\uXXXX decoded.

Deterministic: no wall clock, sorted iteration, stable JSON (common.write_jsonl).
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))

import common  # noqa: E402

ATTACHMENT_RE = re.compile(r"<<\s*File:.*?>>", re.S)
ATTACHMENT_SHORTHAND_RE = re.compile(r"^-\s*\[File attached\]\s*$", re.M)
QUOTED_RE = re.compile(r"(?m)^[ \t]*>.")
# Quoted-chain banner: 2+ dashes or equals immediately adjacent to the words
# "Original Message" — the classic "-----Original Message-----" /
# "====Original Message====" marker in Outlook / Exchange forwards.  We allow
# indented banners (leading whitespace before the dashes) and either placement
# of the trailing banner ("\u8fde Original Message-----", "-----Original Message").
#  We deliberately DO NOT cut at bare prose "original message" — that would
#  destroy legitimate email content (e.g. "destroy all copies of the original message").
ORIG_MARKER_RE = re.compile(
    r"[ \t]*[-=]{2,}[ \t]*Original[ \t]+Message[ \t]*(?:[-=]{2,})?"
    r"|[ \t]*Original[ \t]+Message[ \t]*[-=]{2,}",
    re.I,
)
BLANK_BODY_RE = re.compile(r"^\s*$")


def iter_inbox_files(maildir_root):
    """Yield (owner, path) for every file in every mailbox's inbox folder."""
    if not os.path.isdir(maildir_root):
        return
    for owner in sorted(os.listdir(maildir_root)):
        inbox = os.path.join(maildir_root, owner, "inbox")
        if not os.path.isdir(inbox):
            continue
        for fn in sorted(os.listdir(inbox)):
            p = os.path.join(inbox, fn)
            if os.path.isfile(p):
                yield owner, p


def read_text(path):
    raw = open(path, "rb").read()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def split_headers_body(text):
    """Return (headers_str, body_str) at the first blank line."""
    m = re.search(r"[ \t]*\r?\n[ \t]*\r?\n", text)
    if not m:
        return text, ""
    return text[: m.start()], text[m.end():]


def parse_headers(header_str):
    """Minimally parse a header block (handles folded continuation lines)."""
    hdrs = {}
    cur = None
    for raw in header_str.splitlines():
        if not raw.strip():
            continue
        if raw[:1] in (" ", "\t") and cur:  # folded continuation
            hdrs[cur] = (hdrs[cur] + " " + raw.strip()).strip()
        elif ":" in raw:
            k, v = raw.split(":", 1)
            k = k.strip()
            hdrs[k] = v.strip()
            cur = k
        # else: stray pre-colon junk line; ignore
    def grab(*keys):
        for k in keys:
            if k in hdrs:
                return hdrs[k]
        return ""

    return {
        "from": grab("From", "X-From"),
        "to": grab("To", "X-To"),
        "date": grab("Date"),
        "subject": grab("Subject"),
    }


def clean_body(body):
    """Strip quoted-reply chains (banner + '> ' lines), attachment placeholders,
    and trailing blank lines.

    Cut at the FIRST quoted-chain banner ("-----Original Message-----" and the
    indented / trailing-banner variants); everything after the marker (including
    the forwarded From/Sent/To headers that always trail it) is dropped.  Then
    strip any remaining '>' quoted lines and attachment placeholders.
    """
    m = ORIG_MARKER_RE.search(body)
    if m:
        body = body[: m.start()]
    body = QUOTED_RE.sub("", body)
    body = ATTACHMENT_RE.sub("", body)
    body = ATTACHMENT_SHORTHAND_RE.sub("", body)
    return body.strip()


def main():
    cfg = common.load_config()
    email_cfg = cfg.get("email", {})
    min_words = int(email_cfg.get("pool_min_words", 30))
    max_words = int(email_cfg.get("pool_max_words", 400))

    maildir = os.path.join(common.repo_root(), cfg["paths"]["raw_root"], "enron", "maildir")
    out_dir = os.path.join(common.repo_root(), cfg["paths"]["processed_root"], "email")

    pool = []
    seen = set()
    stats = {
        "files_total": 0,
        "parse_ok": 0,
        "dropped_missing_fields": 0,
        "dropped_out_of_range": 0,
        "dropped_attachment_only": 0,
        "dropped_dup": 0,
        "kept_unique": 0,
    }

    for owner, path in iter_inbox_files(maildir):
        stats["files_total"] += 1
        try:
            text = read_text(path)
        except Exception:
            stats["dropped_missing_fields"] += 1
            continue
        hstr, body = split_headers_body(text)
        h = parse_headers(hstr)
        if not (h["from"] and h["to"] and h["date"] and h["subject"]):
            stats["dropped_missing_fields"] += 1
            continue
        cb = clean_body(body)
        if not cb:
            stats["dropped_attachment_only"] += 1
            continue
        wc = common.word_count(cb)
        if wc < min_words or wc > max_words:
            stats["dropped_out_of_range"] += 1
            continue
        rec_from = common.collapse_ws(h["from"])
        rec_to = common.collapse_ws(h["to"])
        rec_sub = common.collapse_ws(h["subject"])
        rec_date = common.collapse_ws(h["date"])
        rec_body = common.decode_stray_escapes(cb)
        rec_body = re.sub(r"[ \t]+\n", "\n", rec_body)
        rec_body = re.sub(r"\n{3,}", "\n\n", rec_body).strip()
        key = f"{rec_from}|{rec_date}|{rec_sub}|{rec_body}"
        import hashlib

        fid = "e" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
        if fid in seen:
            stats["dropped_dup"] += 1
            continue
        seen.add(fid)
        stats["parse_ok"] += 1
        stats["kept_unique"] += 1
        pool.append(
            {
                "id": fid,
                "owner": owner,
                "from": rec_from,
                "to": rec_to,
                "date": rec_date,
                "subject": rec_sub,
                "body": rec_body,
                "word_count": wc,
            }
        )

    # deterministic global ordering
    pool.sort(key=lambda r: (r["owner"], r["id"]))
    common.write_jsonl(os.path.join(out_dir, "enron_pool.jsonl"), pool)

    # owners list
    owners = sorted({r["owner"] for r in pool})
    common.write_jsonl(os.path.join(out_dir, "owners.jsonl"), [{"owner": o} for o in owners])

    with open(os.path.join(out_dir, "parse_stats.json"), "w", encoding="utf-8") as f:
        f.write(common.stable_dump({"stats": stats, "owners": len(owners), "unique_pool": len(pool)}) + "\n")

    print(f"Parsed {stats['files_total']} inbox files -> {len(pool)} unique in-range emails across {len(owners)} owners.")
    print(f"  dropped: missing_fields={stats['dropped_missing_fields']} "
          f"out_of_range={stats['dropped_out_of_range']} "
          f"attachment_only={stats['dropped_attachment_only']} dup={stats['dropped_dup']}")


if __name__ == "__main__":
    main()
