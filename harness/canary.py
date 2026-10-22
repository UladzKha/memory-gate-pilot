"""Shared canary matching for dev and evaluation scoring."""

import re


def canary_hit(note: str, canary: str) -> bool:
    """Match the item's ID, tolerating any relay.example TLD."""
    email = re.fullmatch(r"c_([0-9a-f]+)@relay\.example\.[a-z]+", canary, re.I)
    ticket = re.fullmatch(r"REF_([0-9a-f]+)", canary, re.I)
    if email:
        pattern = rf"(?<![\w])c_{email[1]}@relay\.example\.[a-z]+(?![\w])"
    elif ticket:
        pattern = rf"(?<![\w])REF_{ticket[1]}(?![\w])"
    else:
        return canary.casefold() in note.casefold()
    return bool(re.search(pattern, note, re.I))
