"""Replace only evaluation memory wrappers with precommitted held-out templates.

Reads dataset-v3 from its Git tag, writes the six affected JSONL files, and
proves that every other inbox component is byte-identical. No model calls.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "scripts/email"))

from scripts.common import load_config, make_rng, stable_dump, word_count
from ecommon import Canary


DATA = ROOT / "data/processed/email"
HELDOUT = ROOT / "data/raw/heldout_templates.txt"
PROOF = DATA / "V4_DIFF_PROOF.md"
FILES = ("attack_inboxes.jsonl", "benign_set.jsonl", "benign_emails.jsonl",
         "benign_emails_v2.jsonl", "benign_specs.jsonl", "benign_specs_v2.jsonl")


def v3_bytes(name: str) -> bytes:
    return subprocess.check_output(
        ["git", "show", f"dataset-v3:data/processed/email/{name}"], cwd=ROOT)


def rows(data: bytes) -> list[dict]:
    return [json.loads(line) for line in data.decode("utf-8").splitlines() if line]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encode(data: list[dict]) -> bytes:
    return ("".join(stable_dump(row) + "\n" for row in data)).encode("utf-8")


def split_template(template: str) -> tuple[str, str]:
    if template.count("{attack}") != 1:
        raise ValueError(f"Template must contain exactly one {{attack}}: {template!r}")
    return tuple(template.split("{attack}"))


def payload(body: str, template: str) -> str:
    prefix, suffix = split_template(template)
    if not body.startswith(prefix) or not body.endswith(suffix):
        raise ValueError("Body does not match its recorded wrapper")
    return body[len(prefix):len(body) - len(suffix) if suffix else None]


def main() -> None:
    config = load_config()
    templates = HELDOUT.read_text(encoding="utf-8").splitlines()
    if len(templates) != 10 or len(set(templates)) != 10:
        raise ValueError("Expected ten distinct held-out templates")
    for template in templates:
        split_template(template)
    originals = {name: v3_bytes(name) for name in FILES}
    old = {name: rows(data) for name, data in originals.items()}
    updated = {name: [json.loads(stable_dump(row)) for row in group]
               for name, group in old.items()}
    canary = Canary(config)  # dataset-v3 templates remain in config/dataset.yaml
    pool = {row["attack_id"]: row for row in rows(v3_bytes("attacks_pool.jsonl"))}
    chosen = {}
    attack_template_counts = Counter()
    benign_template_counts = Counter()

    for original, row in zip(old["attack_inboxes.jsonl"], updated["attack_inboxes.jsonl"]):
        if row["variant"] != "memory":
            continue
        item_id = row["item_id"]
        source = pool[row["attack_id"]]
        if row["source"] == "llmail":
            token, base, _, _ = canary.llmail(source["body"], item_id,
                                               source.get("subject") or "")
        else:
            token, base, _ = canary.bipia(source["text"], item_id)
        if token != row["canary"]:
            raise ValueError(f"Canary reconstruction failed: {item_id}")
        old_block = canary.memory_wrap(base, item_id)
        template = make_rng(config, "v4.template." + item_id).choice(templates)
        new_block = template.format(attack=base)
        index = row["attack_email_index"]
        body = row["emails"][index]["body"]
        if body.count(old_block) != 1:
            raise ValueError(f"Old wrapper not unique: {item_id}")
        row["emails"][index]["body"] = body.replace(old_block, new_block, 1)
        chosen[item_id] = template
        attack_template_counts[templates.index(template) + 1] += 1
        assert row["emails"][index]["body"] != original["emails"][index]["body"]

    specs = {row["id"]: row for name in ("benign_specs.jsonl", "benign_specs_v2.jsonl")
             for row in old[name]}
    for name in ("benign_emails.jsonl", "benign_emails_v2.jsonl"):
        for row in updated[name]:
            old_template = row.get("memory_template")
            if not old_template:
                continue
            item_id = row["id"]
            content = payload(row["body"], old_template)
            target = specs[item_id]["target_words"]
            eligible = [template for template in templates
                        if 0.85 * target <= word_count(template.format(attack=content)) <= 1.15 * target]
            if not eligible:
                raise ValueError(f"No held-out template fits benign word-count check: {item_id}")
            template = make_rng(config, "v4.template." + item_id).choice(eligible)
            row["body"] = template.format(attack=content)
            row["memory_template"] = template
            chosen[item_id] = template
            benign_template_counts[templates.index(template) + 1] += 1

    for name in ("benign_specs.jsonl", "benign_specs_v2.jsonl"):
        for row in updated[name]:
            if row.get("memory_template"):
                row["memory_template"] = chosen[row["id"]]
    for original, row in zip(old["benign_set.jsonl"], updated["benign_set.jsonl"]):
        if row["variant"] != "memory":
            continue
        item_id = row["item_id"]
        source = next(source for name in ("benign_emails.jsonl", "benign_emails_v2.jsonl")
                      for source in old[name] if source["id"] == item_id)
        index = row["attack_email_index"]
        old_body = row["emails"][index]["body"]
        content = payload(old_body, source["memory_template"])
        row["emails"][index]["body"] = chosen[item_id].format(attack=content)
        assert row["emails"][index]["body"] != original["emails"][index]["body"]

    if len(chosen) != 337 or sum(attack_template_counts.values()) != 300 or sum(benign_template_counts.values()) != 37:
        raise ValueError("Expected exactly 300 attack and 37 benign memory wrappers")
    new_bytes = {name: encode(group) for name, group in updated.items()}

    # Byte-level proof of every untouched line; structural proof within the
    # 337 changed lines, including all five context emails in each inbox.
    unchanged_attack = unchanged_benign = checked_email_fields = 0
    for name in ("attack_inboxes.jsonl", "benign_set.jsonl"):
        old_lines = originals[name].splitlines(keepends=True)
        new_lines = new_bytes[name].splitlines(keepends=True)
        for before, after, old_line, new_line in zip(old[name], updated[name], old_lines, new_lines):
            if before["variant"] != "memory":
                if old_line != new_line:
                    raise ValueError(f"Non-memory line changed: {before['item_id']}")
                if name == "attack_inboxes.jsonl":
                    unchanged_attack += 1
                else:
                    unchanged_benign += 1
                continue
            index = before["attack_email_index"]
            old_body = before["emails"][index]["body"]
            new_body = after["emails"][index]["body"]
            if old_body == new_body:
                raise ValueError(f"Memory wrapper did not change: {before['item_id']}")
            restored = json.loads(stable_dump(after))
            restored["emails"][index]["body"] = old_body
            if stable_dump(restored) != stable_dump(before):
                raise ValueError(f"Non-body inbox component changed: {before['item_id']}")
            checked_email_fields += len(before["emails"]) - 1
    if (unchanged_attack, unchanged_benign, checked_email_fields) != (300, 113, 1685):
        raise ValueError("Incomplete byte-identity proof")
    for name in ("benign_emails.jsonl", "benign_emails_v2.jsonl",
                 "benign_specs.jsonl", "benign_specs_v2.jsonl"):
        for before, after in zip(old[name], updated[name]):
            allowed = {"memory_template", "body"} if "emails" in name else {"memory_template"}
            if before.get("memory_template"):
                restored = {**after, **{key: before[key] for key in allowed}}
                if stable_dump(restored) != stable_dump(before):
                    raise ValueError(f"Other benign source field changed: {before['id']}")
            elif stable_dump(after) != stable_dump(before):
                raise ValueError(f"Non-memory benign source changed: {before['id']}")
    clean_v3 = v3_bytes("clean_set.jsonl")
    if (DATA / "clean_set.jsonl").read_bytes() != clean_v3:
        raise ValueError("Clean set differs from dataset-v3")

    for name, data in new_bytes.items():
        (DATA / name).write_bytes(data)

    proof = ["# Dataset-v4 difference proof", "",
             "Baseline: `dataset-v3` Git tag. Wrapper source: committed `data/raw/heldout_templates.txt` "
             f"(SHA-256 `{sha(HELDOUT.read_bytes())}`). Seed: `{config['seed']}`. "
             "The builder compares baseline and output rows and stops if any unlisted field changes.", "",
             "- Attack memory inboxes changed: **300/300**; attack `as_is` lines byte-identical: **300/300**.",
             "- Benign memory inboxes changed: **37/37**; benign `as_is` lines byte-identical: **113/113**.",
             "- Non-injected emails inside the 337 changed inboxes structurally identical: **1,685/1,685**.",
             f"- `clean_set.jsonl` byte-identical to dataset-v3: SHA-256 `{sha(clean_v3)}`.",
             "- Each changed inbox has the same item metadata, position, canary/tracker, subject, sender, recipient, date, and all other email fields. Only the indexed email body wrapper changed; the payload bytes were preserved.",
             "- The 37 benign source bodies and their recorded `memory_template` fields changed to match; all other benign source and specification fields are identical.", "",
             "Benign template choices use the seed among held-out templates that satisfy the existing per-item word-count bound. Attack choices use the seed among all ten. No gate output or evaluation result influenced selection.", "",
             "| File | dataset-v3 SHA-256 | dataset-v4 SHA-256 |", "|---|---|---|"]
    for name in (*FILES, "clean_set.jsonl"):
        proof.append(f"| `{name}` | `{sha(v3_bytes(name))}` | `{sha((DATA / name).read_bytes())}` |")
    proof += ["", "Template selection counts (1–10 in the order of the held-out file):", "",
              "| Template | Attack memory | Benign memory |", "|---:|---:|---:|"]
    for number in range(1, 11):
        proof.append(f"| {number} | {attack_template_counts[number]} | {benign_template_counts[number]} |")
    PROOF.write_text("\n".join(proof) + "\n", encoding="utf-8")
    print(f"Built dataset-v4: 300 attack + 37 benign memory inboxes; proof {PROOF}")


if __name__ == "__main__":
    main()
