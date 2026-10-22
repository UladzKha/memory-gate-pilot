"""Fail closed when a frozen input differs from the build report."""

import hashlib
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = REPO_ROOT / "data/processed/email"
REPORT_PATH = DATASET_DIR / "REPORT.md"
DATASET_FILES = ("attack_inboxes.jsonl", "benign_set.jsonl", "clean_set.jsonl")


def verify_dataset(dataset: str = "eval") -> None:
    """Check all three final JSONL files against REPORT.md before any run."""
    if dataset not in ("eval", "dev"):
        raise ValueError(f"Unknown dataset: {dataset}")
    directory = DATASET_DIR if dataset == "eval" else REPO_ROOT / "data/processed/email_dev"
    report_path = directory / "REPORT.md"
    report = report_path.read_text(encoding="utf-8")
    for name in DATASET_FILES:
        pattern = re.compile(
            rf"^\| `data/processed/{directory.name}/{re.escape(name)}`(?: \([^|]*\))?"
            rf" \| `([0-9a-f]{{64}})` \|$",
            re.MULTILINE,
        )
        matches = pattern.findall(report)
        if len(matches) != 1:
            raise ValueError(f"Expected exactly one SHA-256 entry for {name} in {report_path}")
        path = directory / name
        with path.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != matches[0]:
            raise ValueError(f"SHA-256 mismatch for {path}: expected {matches[0]}, got {actual}")
