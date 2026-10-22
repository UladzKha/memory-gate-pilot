#!/usr/bin/env python3
"""Add unused real Enron deleted_items messages for v2 benign context.

Uses the same parsing, body cleaning, 30..400 word filter and identity hash as
01_parse_enron.py. The original enron_pool.jsonl is never rewritten.
"""

import hashlib
import importlib
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ecommon as E
from common import collapse_ws, decode_stray_escapes, read_jsonl, word_count, write_jsonl

parse = importlib.import_module("01_parse_enron")


def main():
    root = Path(__file__).resolve().parents[2]
    clean_owners = {r["owner"] for r in read_jsonl(E.data_path("mailbox_split.jsonl"))
                    if r["group"] == "clean"}
    known = {r["id"] for r in read_jsonl(E.data_path("enron_pool.jsonl"))}
    for name in ("attack_inboxes", "benign_set", "clean_set"):
        for row in read_jsonl(root / "data/processed/email_dev" / (name + ".jsonl")):
            known.update(ep["id"] for ep in row["emails"])
    out = []
    for owner in sorted(clean_owners):
        folder = root / "data/raw/enron/maildir" / owner / "deleted_items"
        if not folder.is_dir():
            continue
        for path in sorted(folder.iterdir()):
            if not path.is_file():
                continue
            headers, body = parse.split_headers_body(parse.read_text(path))
            h = parse.parse_headers(headers)
            if not all(h.values()):
                continue
            cleaned = parse.clean_body(body)
            wc = word_count(cleaned)
            if not 30 <= wc <= 400:
                continue
            sender = collapse_ws(h["from"])
            to = collapse_ws(h["to"])
            date = collapse_ws(h["date"])
            subject = collapse_ws(h["subject"])
            cleaned = decode_stray_escapes(cleaned)
            cleaned = re.sub(r"[ \t]+\n", "\n", cleaned)
            cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
            if "Original Message" in cleaned or "Original Message" in subject:
                continue
            ident = "e" + hashlib.sha1(f"{sender}|{date}|{subject}|{cleaned}".encode()).hexdigest()[:16]
            if ident in known:
                continue
            known.add(ident)
            out.append({"id": ident, "owner": owner, "from": sender, "to": to,
                        "date": date, "subject": subject, "body": cleaned, "word_count": wc})
    out.sort(key=lambda row: (row["owner"], row["id"]))
    output = E.data_path("enron_v2_context_pool.jsonl")
    write_jsonl(output, out)
    print(f"Supplemental Enron deleted_items pool: {len(out)} unique eligible messages across "
          f"{len({r['owner'] for r in out})} clean owners")


if __name__ == "__main__":
    main()
