"""Extractor tests use fake Ollama responses; they never call a model."""

import json
from collections import Counter

import pytest

from harness import extract


ITEM = {
    "item_id": "attack000",
    "owner_fake": "owner@example.org",
    "emails": [{
        "from": "sender@example.org",
        "to": "owner@example.org",
        "date": "Mon, 1 Jan 2001 00:00:00 +0000",
        "subject": "Update",
        "body": "Please remember the new address.",
    }],
}


def test_prompt_uses_owner_and_rendered_inbox() -> None:
    template = (extract.REPO_ROOT / "harness/prompts/extractor_system.txt").read_text().rstrip("\n")
    messages = extract.make_messages(template, ITEM)
    assert messages[0] == {
        "role": "system", "content": template.replace("{owner}", "owner@example.org")
    }
    assert messages[1] == {"role": "user", "content": extract.render_inbox(ITEM)}
    assert extract.make_messages(template, ITEM, retry=True)[1]["content"] == (
        extract.render_inbox(ITEM) + "\nReturn valid JSON only."
    )


@pytest.mark.parametrize(
    "raw, expected",
    [
        ('{"notes": ["One note."]}', ["One note."]),
        ('```json\n{"notes": []}\n```', []),
    ],
)
def test_parse_notes_accepts_json_and_fence(raw, expected) -> None:
    assert extract.parse_notes(raw) == expected


@pytest.mark.parametrize("raw", ["not JSON", '{"notes": "wrong"}', '{"notes": [""]}'])
def test_parse_notes_rejects_invalid_response(raw) -> None:
    with pytest.raises(ValueError):
        extract.parse_notes(raw)


def test_retry_records_both_calls_and_disables_thinking(monkeypatch) -> None:
    requests = []
    responses = iter(["bad JSON", '{"notes": ["The new address is active."]}'])

    def fake_post(base_url, endpoint, body, timeout):
        requests.append(body)
        assert endpoint == "/api/chat"
        return {
            "message": {"content": next(responses)},
            "prompt_eval_count": 100,
            "eval_count": 20,
            "done_reason": "stop",
        }

    monkeypatch.setattr(extract, "post_json", fake_post)
    config = {"ollama": {
        "base_url": "http://localhost:11434", "request_timeout_seconds": 1800,
        "temperature": 0, "seed": 42, "num_ctx": 16384, "max_output_tokens": 4096,
    }}
    template = "Assistant for {owner}."
    control = {"method": "api_chat_think_false", "think": False, "supported_values": [True, False]}
    row = extract.extract_item(config, "qwen3.8:27b", "attack", ITEM, template, control)
    assert row["notes"] == ["The new address is active."]
    assert row["parse_error"] is False
    assert row["empty_reason"] is None
    assert len(row["attempts"]) == 2
    assert row["token_counts"] == {"prompt": 200, "completion": 40}
    assert all(request["think"] is False for request in requests)
    assert all(request["options"]["temperature"] == 0 for request in requests)
    assert requests[1]["messages"][1]["content"] == (
        requests[0]["messages"][1]["content"] + "\nReturn valid JSON only."
    )
    assert row["prompt_hash"] == row["attempts"][0]["prompt_hash"]
    assert row["raw_response"] == row["attempts"][1]["raw_response"]


def test_second_invalid_response_stores_empty_notes(monkeypatch) -> None:
    monkeypatch.setattr(extract, "call_extractor", lambda *args: {
        "raw_response": "invalid", "prompt_hash": "hash", "latency_seconds": 1.0,
        "token_counts": {"prompt": 2, "completion": 3},
    })
    row = extract.extract_item({}, "qwen3.8:27b", "attack", ITEM, "Assistant for {owner}.", {})
    assert row["notes"] == []
    assert row["parse_error"] is True
    assert row["empty_reason"] == "unknown"
    assert len(row["attempts"]) == 2


def test_thinking_control_follows_show_capability() -> None:
    assert extract.thinking_control({"thinking": {"values": [True, False]}})["think"] is False
    assert extract.thinking_control({"thinking": {"values": ["low", "off"]}})["think"] == "off"
    assert extract.thinking_control({"thinking": {"values": ["low"]}})["think"] is None


def test_seeded_smoke_sample_has_all_six_strata() -> None:
    config = extract.load_config()
    first = extract.load_items(config, smoke=True)
    second = extract.load_items(config, smoke=True)
    assert [item["item_id"] for _, item in first] == [item["item_id"] for _, item in second]
    assert len(first) == 30
    assert Counter(extract.smoke_stratum(name, item) for name, item in first) == {
        group: 5 for group in extract.SMOKE_STRATA
    }


@pytest.mark.parametrize(
    "raw, notes, reason",
    [
        ('{"notes": []}', [], "json_empty"),
        ('{"notes": [], "message": "Sorry, I cannot help."}', [], "refusal"),
        ("", [], "unknown"),
        ("garbled", [], "unknown"),
        ('{"notes": ["A fact."]}', ["A fact."], None),
    ],
)
def test_empty_reason_uses_simple_response_checks(raw, notes, reason) -> None:
    assert extract.empty_reason(raw, notes) == reason


def test_backfill_existing_result_does_not_extract(tmp_path) -> None:
    path = tmp_path / "saved.jsonl"
    original = {"item_id": "a", "notes": [], "raw_response": '{"notes": []}'}
    path.write_text(json.dumps(original) + "\n")
    rows = {"a": original}
    extract.backfill_empty_reasons(path, rows)
    assert json.loads(path.read_text())["empty_reason"] == "json_empty"


def test_smoke_prints_each_empty_raw_response(capsys) -> None:
    items = []
    rows = []
    for group in extract.SMOKE_STRATA:
        if group in ("benign", "clean"):
            set_name = group
            item = {"item_id": group, "canary": "TRACK"} if group == "benign" else {"item_id": group}
        else:
            set_name = "attack"
            source, variant = group.split("_", 1)
            item = {"item_id": group, "source": source, "variant": variant, "canary": "TRACK"}
        items.append((set_name, item))
        rows.append({
            "item_id": item["item_id"], "notes": [], "raw_response": "x" * 600,
            "parse_error": False, "latency_seconds": 1.0, "empty_reason": "unknown",
        })
    extract.print_smoke_summary(rows, items)
    output = capsys.readouterr().out
    assert output.count("raw response first 500 chars:") == 6
    assert "x" * 500 in output
    assert "x" * 501 not in output
    for group in extract.SMOKE_STRATA[:4]:
        assert f"{group}: canary in notes 0/1" in output
