"""Check the complete frozen corpus for metadata leakage into model input."""

import hashlib
import json
from collections import Counter

import pytest

from harness import dataset
from harness.dataset import DATASET_DIR, DATASET_FILES, verify_dataset
from harness.render import render_inbox


FORBIDDEN = (
    "bipia",
    "llmail",
    "enron-context",
    "benign",
    "attack_id",
    "expected_outcome",
)


def test_dataset_matches_report() -> None:
    verify_dataset()


def test_dataset_rejects_mismatched_report_hash(tmp_path, monkeypatch) -> None:
    report = dataset.REPORT_PATH.read_text(encoding="utf-8")
    actual_hash = hashlib.sha256((DATASET_DIR / DATASET_FILES[0]).read_bytes()).hexdigest()
    assert report.count(actual_hash) == 1
    wrong_hash = "0" * 64
    report = report.replace(actual_hash, wrong_hash)
    changed_report = tmp_path / "REPORT.md"
    changed_report.write_text(report, encoding="utf-8")
    monkeypatch.setattr(dataset, "REPORT_PATH", changed_report)
    with pytest.raises(ValueError, match="SHA-256 mismatch for"):
        verify_dataset()


def test_rendered_inboxes_do_not_leak_labels() -> None:
    verify_dataset()
    seen = {}
    leaks = []
    natural_banned = Counter()
    natural_labels = Counter()
    printed_attack = False
    for name in DATASET_FILES:
        seen[name] = 0
        with (DATASET_DIR / name).open(encoding="utf-8") as stream:
            for line in stream:
                item = json.loads(line)
                rendered = render_inbox(item)
                if name == "attack_inboxes.jsonl" and not printed_attack:
                    print(f"Rendered attack inbox ({item['item_id']}):\n{rendered}")
                    printed_attack = True
                lowered = rendered.lower()
                original_text = "\n".join(
                    f"{email['subject']}\n{email['body']}" for email in item["emails"]
                ).lower()
                for marker in FORBIDDEN:
                    natural_banned[marker] += original_text.count(marker)
                    if marker in lowered and marker not in original_text:
                        leaks.append((name, item["item_id"], marker))
                label_values = {
                    "item_id": {item["item_id"]},
                    "attack_id": {item["attack_id"]} if "attack_id" in item else set(),
                    "source": {item["source"]} | {email["source"] for email in item["emails"]},
                    "expected_outcome": {item["expected_outcome"]} if "expected_outcome" in item else set(),
                    "id": {email["id"] for email in item["emails"]},
                    "canary": {item["canary"]} if "canary" in item else set(),
                }
                for field, values in label_values.items():
                    for value in values:
                        needle = value.lower()
                        natural_labels[field] += original_text.count(needle)
                        if needle in lowered and needle not in original_text:
                            leaks.append((name, item["item_id"], field, value))
                seen[name] += 1
    print(f"Natural banned-word occurrences in subject/body: {dict(natural_banned)}")
    print(f"Natural metadata-value occurrences in subject/body: {dict(natural_labels)}")
    assert seen == {
        "attack_inboxes.jsonl": 600,
        "benign_set.jsonl": 60,
        "clean_set.jsonl": 300,
    }
    assert leaks == []


def test_render_uses_only_five_email_fields() -> None:
    item = {
        "item_id": "secret-item-id",
        "attack_id": "secret-attack-id",
        "emails": [{
            "from": "sender@example.org",
            "to": "reader@example.org",
            "date": "Mon, 1 Jan 2001 00:00:00 +0000",
            "subject": "A subject",
            "body": "Body text",
            "id": "secret-email-id",
            "source": "secret-source",
            "canary": "secret-canary",
            "expected_outcome": "secret-label",
        }],
    }
    assert render_inbox(item) == (
        "From: sender@example.org\n"
        "To: reader@example.org\n"
        "Date: Mon, 1 Jan 2001 00:00:00 +0000\n"
        "Subject: A subject\n\nBody text"
    )
