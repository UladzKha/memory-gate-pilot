"""Export every saved Level 3 full-guard clean denial, using DEV inputs only."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re

from harness.dataset import verify_dataset
from harness.defend import load_extractions
from memgate import check_batch
from memgate.guard import _canonical


ROOT = Path(__file__).resolve().parents[1]
DEV = ROOT / "data/processed/email_dev"
EXTRACT = ROOT / "results/dev/extract"
L3 = ROOT / "results/dev/l3"
OUTPUT = ROOT / "results/checks/gate_dev_clean_denials.md"
TYPES = ("email", "ref", "account", "url", "path", "amount")
REASON = re.compile(r"^.+ uses (.+) from untrusted memory; ask the user before acting$")


def rows(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def excerpt(email: dict | None, identifier: str) -> str:
    if email is None:
        return "No linked source email."
    content = "\n".join(str(email.get(field, "")) for field in ("subject", "body"))
    position = content.casefold().find(identifier.casefold())
    if position < 0:
        position = 0
    start = max(0, position - 110)
    end = min(len(content), position + max(len(identifier), 170))
    part = content[start:end].replace("\r", " ").replace("\n", " ")
    return ("…" if start else "") + part + ("…" if end < len(content) else "")


def main() -> None:
    verify_dataset("dev")
    clean = {item["item_id"]: item for item in rows(DEV / "clean_set.jsonl")}
    findings = []
    counts: dict[str, Counter] = {}
    for path in sorted(L3.glob("*__gate_full.jsonl")):
        model = path.name.removesuffix("__gate_full.jsonl")
        extractions = {row["item_id"]: row for row in load_extractions(EXTRACT / f"{model}.jsonl", model)}
        counts[model] = Counter()
        for row in rows(path):
            if row["set"] != "clean":
                continue
            denied = [call for call in row["calls"] if call["denied"]]
            if not denied:
                continue
            item_id = row["item_id"]
            item = clean[item_id]
            notes = extractions[item_id]["notes"]
            decisions = check_batch(notes, item["emails"], item["owner"])
            retained = [(note, decision) for note, decision in zip(notes, decisions)
                        if decision.outcome != "block"]
            memory = row["memory_entries"]
            if len(retained) != len(memory) or any(
                note != entry["text"] or decision.rules != entry["rules"]
                for (note, decision), entry in zip(retained, memory)
            ):
                raise ValueError(f"Stored DEV memory provenance changed: {model} {item_id}")
            for call in denied:
                match = REASON.fullmatch(call["reason"] or "")
                if not match:
                    raise ValueError(f"Unrecognized guard denial: {model} {item_id}")
                identifier = match[1]
                kind = _canonical(identifier).partition(":")[0]
                if kind not in TYPES:
                    raise ValueError(f"Unknown denied identifier type: {identifier}")
                matches = [((note, decision), entry) for (note, decision), entry in zip(retained, memory)
                           if not entry["source_trusted"] and identifier in entry["targets"]]
                if not matches:
                    raise ValueError(f"Denied identifier absent from stored memory: {model} {item_id}: {identifier}")
                (note, decision), entry = matches[0]
                source = item["emails"][decision.source_index] if decision.source_index is not None else None
                findings.append((model, item_id, call, identifier, kind, note, entry, decision.source_index, source))
                counts[model][kind] += 1

    lines = ["# DEV full-guard clean denials", "",
             "Every denied mock tool call on a selected clean DEV item is listed below. Counts are per call; one item can have several denials. The linked source is recomputed from the saved DEV extraction and DEV inbox. A rule value of `none` means the note was stored as `allow`, but its source sender was not trusted, so the action guard still denied its target.", "",
             "| Model | Email | REF | Account | URL | Path | Amount | Total |",
             "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for model in sorted(counts):
        counter = counts[model]
        lines.append(f"| {model} | " + " | ".join(str(counter[kind]) for kind in TYPES) + f" | {sum(counter.values())} |")
    total = sum(counts.values(), Counter())
    lines.append("| **All models** | " + " | ".join(str(total[kind]) for kind in TYPES) + f" | **{sum(total.values())}** |")
    for number, (model, item_id, call, identifier, kind, note, entry, source_index, source) in enumerate(findings, 1):
        rules = ", ".join(entry["rules"]) or "none"
        lines += ["", f"## {number}. {model} — {item_id}", "",
                  f"- Denied identifier: `{identifier}` ({kind})",
                  f"- Memory outcome and rules: `{entry['outcome']}`; `{rules}`",
                  f"- Source email: index `{source_index}`, sender `{entry['source_sender']}`",
                  "- Memory note:", "", "~~~text", note, "~~~", "",
                  "- Source email excerpt:", "", "~~~text", excerpt(source, identifier), "~~~", "",
                  "- Denied tool call:", "", "~~~json",
                  json.dumps({"tool_name": call["tool_name"], "args": call["args"],
                              "round": call["round"], "reason": call["reason"]}, ensure_ascii=False, indent=2),
                  "~~~"]
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Exported {len(findings)} DEV clean denials to {OUTPUT}")


if __name__ == "__main__":
    main()
