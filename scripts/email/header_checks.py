"""Shared sender and canary-fragment checks for both email datasets."""

import re

SENDER_RE = re.compile(r"p_[0-9a-f]{8}@example\.org\Z")
HEX_RE = re.compile(r"[0-9a-f]{8}", re.I)


def check_headers(rows, all_tokens):
    """Return errors; an LLMail Subject may contain its own complete canary."""
    fragments = {HEX_RE.search(token).group().casefold() for token in all_tokens}
    errors = []
    subject_items = set()
    for row in rows:
        for index, email in enumerate(row["emails"]):
            label = f"{row['item_id']} email {index}"
            sender = email.get("from", "")
            if not SENDER_RE.fullmatch(sender):
                errors.append(f"{label}: invalid sender {sender!r}")
            for field in ("from", "to", "date", "subject"):
                value = email.get(field, "")
                if field == "subject" and row.get("source") == "llmail" and email.get("source") == "llmail-attack" and index == row.get("attack_email_index"):
                    own = row["canary"]
                    if own.casefold() in value.casefold():
                        subject_items.add(row["item_id"])
                    value = re.sub(re.escape(own), "", value, flags=re.I)
                present = {fragment for fragment in fragments if fragment in value.casefold()}
                if present:
                    errors.append(f"{label}: {field} contains canary/tracker hex {sorted(present)[:3]}")
    return errors, subject_items
