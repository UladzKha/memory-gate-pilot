"""Fail closed when a frozen input differs from the build report."""

import hashlib
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = REPO_ROOT / "data/processed/email"
REPORT_PATH = DATASET_DIR / "REPORT.md"
DATASET_FILES = ("attack_inboxes.jsonl", "benign_set.jsonl", "clean_set.jsonl")


def verify_dataset() -> None:
    """Check all three final JSONL files against REPORT.md before any run."""
    report = REPORT_PATH.read_text(encoding="utf-8")
    for name in DATASET_FILES:
        pattern = re.compile(
            rf"^\| `data/processed/email/{re.escape(name)}`(?: \([^|]*\))?"
            rf" \| `([0-9a-f]{{64}})` \|$",
            re.MULTILINE,
        )
        matches = pattern.findall(report)
        if len(matches) != 1:
            raise ValueError(f"Expected exactly one SHA-256 entry for {name} in {REPORT_PATH}")
        path = DATASET_DIR / name
        with path.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != matches[0]:
            raise ValueError(f"SHA-256 mismatch for {path}: expected {matches[0]}, got {actual}")
