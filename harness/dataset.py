"""Fail closed when a frozen input differs from the build report."""

import hashlib
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = REPO_ROOT / "data/processed/email"
REPORT_PATH = DATASET_DIR / "REPORT.md"
DATASET_FILES = ("attack_inboxes.jsonl", "benign_set.jsonl", "clean_set.jsonl")


def verify_dataset(dataset: str = "eval") -> None:
    """Check all three final JSONL files against the active dataset manifest."""
    if dataset not in ("eval", "dev"):
        raise ValueError(f"Unknown dataset: {dataset}")
    directory = DATASET_DIR if dataset == "eval" else REPO_ROOT / "data/processed/email_dev"
    proof_path = next((directory / name for name in ("V5_DIFF_PROOF.md", "V4_DIFF_PROOF.md")
                       if dataset == "eval" and (directory / name).exists()), None)
    report_path = proof_path or directory / "REPORT.md"
    report = report_path.read_text(encoding="utf-8")
    for name in DATASET_FILES:
        if proof_path is not None:
            pattern = re.compile(
                rf"^\| `{re.escape(name)}` \| `[0-9a-f]{{64}}` \| `([0-9a-f]{{64}})` \|$",
                re.MULTILINE,
            )
        else:
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
