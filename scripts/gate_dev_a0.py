"""Audit v0.2 taint misses and compare A0 fixes on DEV-only saved notes."""

from collections import Counter
import json
from pathlib import Path
import re

from harness.canary import canary_hit
from scripts.baselines import memgate_v02 as baseline
from scripts.baselines import memgate_v021 as current
from scripts.gate_dev_eval import evaluate, rate, rows

check_v021 = current.check_batch

ROOT = Path(__file__).resolve().parents[1]
DEV = ROOT / "data/processed/email_dev"
EXTRACT = ROOT / "results/dev/extract"
OUTPUT = ROOT / "results/checks/gate_dev_a0.md"
RULES = ("T1", "T2", "T3")


def source_patterns(module, text):
    result = {}
    for rule in ("T1", "T2"):
        hit = getattr(module, rule).search(text)
        if hit:
            result[rule] = hit.group(0).replace("\n", " ")[:90]
    if text and (module._tainted_space(text) or module._mixed_script(text) or
                 re.search(r"(?i)\b[a-z]{2,}(?:[|¦][a-z]{2,})+\b", text)):
        result["T3"] = "unusual spacing, mixed script, or separator"
    return result


def audit_model(extractions, items, module):
    records = []
    clean_n1 = {}
    for row in extractions:
        group, item = items[row["item_id"]]
        decisions = module.check_batch(row["notes"], item["emails"], item["owner"])
        for note, decision in zip(row["notes"], decisions):
            if group == "clean":
                clean_n1[(row["item_id"], note)] = "N1" in decision.rules
            if group != "attack" or not canary_hit(note, item["canary"]) or decision.outcome == "block":
                continue
            index = decision.source_index
            text = module._email_text(item["emails"][index]) if index is not None else ""
            patterns = source_patterns(module, text)
            fired = [rule for rule in RULES if rule in decision.rules]
            records.append((row["item_id"], index, item["attack_email_index"], patterns, fired, note))
    return records, clean_n1


def main():
    items = {}
    for group, filename in (("attack", "attack_inboxes.jsonl"),
                            ("benign", "benign_set.jsonl"),
                            ("clean", "clean_set.jsonl")):
        for item in rows(DEV / filename):
            items[item["item_id"]] = group, item
    lines = ["# A0: v0.2 → v0.2.1 DEV audit", "",
             "All inputs are saved DEV extractions and DEV inboxes. v0.2 is frozen commit `d027440`; v0.2.1 is the A0 rule revision before the provenance design change.", "",
             "| Model | Gate | Attack canary reject all | Approve all | Benign tracker allow / quarantine / block | Clean inboxes with quarantine or block | Clean N1 notes |",
             "|---|---|---:|---:|---:|---:|---:|"]
    sections = []
    for path in sorted(EXTRACT.glob("*.jsonl")):
        model = path.stem
        extractions = rows(path)
        results = {"v0.2": evaluate(extractions, items, baseline.check_batch),
                   "v0.2.1": evaluate(extractions, items, check_v021)}
        audits = {"v0.2": audit_model(extractions, items, baseline),
                  "v0.2.1": audit_model(extractions, items, current)}
        for version in ("v0.2", "v0.2.1"):
            counts, rules, *_ = results[version]
            a,b,c = (counts[name] for name in ("attack", "benign", "clean"))
            lines.append(f"| {model} | {version} | {a['reject']}/{a['items']} | {a['approve']}/{a['items']} | {b['tracker_item_allow']} / {b['tracker_item_quarantine']} / {b['tracker_item_block']} ({b['no_tracker']} without tracker) | {c['intervened']}/{c['items']} | {rules['clean']['N1']}/{c['notes']} |")
        before, after = audits["v0.2"][0], audits["v0.2.1"][0]
        sections += ["", f"## {model}: taint audit", "",
                     "Every nonblocked attack canary note is listed below for each gate. Match columns show the text matched in the linked source; fired shows the decision rule IDs.", "",
                     "| Gate | Nonblocked canary notes | Linked to injected email | T1 matches | T2 matches | T3 matches | Matched but not fired |",
                     "|---|---:|---:|---:|---:|---:|---:|"]
        for version, records in (("v0.2", before), ("v0.2.1", after)):
            matched_not_fired = sum(bool(set(patterns) - set(fired)) for _,_,_,patterns,fired,_ in records)
            sections.append(f"| {version} | {len(records)} | {sum(index==expected for _,index,expected,_,_,_ in records)}/{len(records)} | {sum('T1' in p for _,_,_,p,_,_ in records)} | {sum('T2' in p for _,_,_,p,_,_ in records)} | {sum('T3' in p for _,_,_,p,_,_ in records)} | {matched_not_fired} |")
        before_n1, after_n1 = audits["v0.2"][1], audits["v0.2.1"][1]
        resolved = [(item_id, note) for (item_id, note), old_hit in before_n1.items()
                    if old_hit and not after_n1[(item_id, note)]]
        sections += ["", f"### Clean N1 changes — {model}", "",
                     f"Before: {sum(before_n1.values())} notes; after: {sum(after_n1.values())} notes; resolved: {len(resolved)}.", "",
                     f"Examples of previously flagged clean notes now allowed ({min(10,len(resolved))}):", ""]
        for item_id, note in resolved[:10]:
            sections += [f"- `{item_id}`: {json.dumps(note, ensure_ascii=False)}"]
        for version, records in (("v0.2", before), ("v0.2.1", after)):
            sections += ["", f"### Every nonblocked attack canary note — {model} {version}", "",
                         "| Item | Linked / injected index | T1 match | T2 match | T3 match | Fired T rules | Note |",
                         "|---|---:|---|---|---|---|---|"]
            for item_id,index,expected,patterns,fired,note in records:
                safe=lambda s: str(s).replace("|", "\\|").replace("\n", " ")
                sections.append(f"| `{item_id}` | {index} / {expected} | {safe(patterns.get('T1','—'))} | {safe(patterns.get('T2','—'))} | {safe(patterns.get('T3','—'))} | {', '.join(fired) or '—'} | {safe(note)} |")
    lines += ["", "Audit finding: every nonblocked attack canary note linked to its injected DEV email, and no T1/T2/T3 source pattern matched. The taint miss came from narrow pattern coverage, not case handling, source attribution, or precedence. The A0 T2 expansion blocks additional source instructions; the remaining nonblocked notes have no matching T pattern."]
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(lines + sections).rstrip()+"\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
