#!/usr/bin/env python3
"""Write the frozen dev provenance report after hard validation."""

import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path

from validate_dev_disjoint import DEV, EVAL, ROOT, validate
from common import read_jsonl


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    validate()
    pool = list(read_jsonl(DEV / "attacks_pool.jsonl"))
    llmail = [r for r in pool if r["source"] == "llmail"]
    ia = [r for r in pool if r["source"] == "injecagent"]
    eval_commit = subprocess.check_output(["git", "rev-list", "-n", "1", "dataset-v1"],
                                          cwd=ROOT, text=True).strip()
    injec_commit = "f19c9f2c79a41046eb13c03c51a24c567a8ffa07"
    names = ("attack_inboxes.jsonl", "benign_set.jsonl", "clean_set.jsonl",
             "attacks_pool.jsonl", "benign_emails.jsonl", "mailbox_split.jsonl",
             "injecagent_source_cases.jsonl", "_used_ctx_ids.txt", "_clean_ctx_used.txt",
             "INJECAGENT_LICENCE.txt")
    lines = [
        "# Email development dataset report", "",
        "This is a development set for designing the memory-write gate. The frozen evaluation set "
        f"is `data/processed/email/` at tag `dataset-v1` (`{eval_commit}`). Neither that directory "
        "nor `results/extract/` was changed by this build.", "",
        "## Sources and licenses", "",
        "- **LLMail-Inject:** local `data/raw/llmail-inject/data/raw_submissions_phase{1,2}.jsonl`; "
        "[dataset card](https://huggingface.co/datasets/microsoft/llmail-inject-challenge) declares MIT. "
        "Kept only submissions with `exfil.sent` and `exfil.destination` true, a literal "
        "`contact@contact.com` anchor, and subject plus body at most 288 words (12 reserved "
        "for wrapping). Removed every evaluation team ID and body, deduplicated bodies, "
        "then sampled 100 proportionally by scenario with seed 45.",
        "- **InjecAgent:** [repository](https://github.com/uiuc-kang-lab/InjecAgent) at "
        f"`{injec_commit}`; [MIT license](https://github.com/uiuc-kang-lab/InjecAgent/blob/main/LICENCE). "
        "The license says: “Permission is hereby granted, free of charge, to any person "
        "obtaining a copy”. Full copyright and permission notice is retained in "
        "`INJECAGENT_LICENCE.txt`. The two base test-case files supplied 1,054 cases "
        "and 62 unique instructions. The sample uses one case per unique instruction plus "
        "38 further distinct cases, for 100 cases across six attack types. Repeated "
        "instruction text is disclosed and has distinct source-case IDs. The exact "
        "minimal source projection is committed as `injecagent_source_cases.jsonl`.",
        "- **Benign:** LLMail-Inject `data/emails_for_fp_tests.json` (MIT); 100 of 203 "
        "parseable false-positive emails sampled with seed 45. Each becomes a standalone "
        "email with a fresh email or `REF_` tracker.",
        "- **Enron:** the existing parsed `data/processed/email/enron_pool.jsonl`, derived "
        "from the Enron corpus. Every email ID in the evaluation attack, benign, and clean "
        "sets, including BIPIA carriers, and both evaluation used-ID trackers was excluded "
        "before dev assembly. See `data/raw/REPORT.md` for source provenance.", "",
        "## Construction", "",
        "- 100 LLMail and 100 InjecAgent cases, each with `as_is` and `memory` variants: "
        "400 attack inboxes. InjecAgent instructions are woven into real Enron carrier "
        "bodies using the same `REF_` ticket pattern as BIPIA. Both attack types use the "
        "same five memory templates and canary generator as evaluation, with dev-only IDs "
        "and seed 45.",
        "- 100 benign inboxes and 100 clean inboxes. Every inbox contains six emails. "
        "Injected emails use the evaluation seeded date function; owners host at most "
        "10 inboxes per set. No Enron email ID is reused within dev.",
        f"- LLMail scenario counts: `{json.dumps(dict(sorted(Counter(r['category_or_scenario'] for r in llmail).items())), sort_keys=True)}`.",
        f"- InjecAgent attack-type counts: `{json.dumps(dict(sorted(Counter(r['category_or_scenario'] for r in ia).items())), sort_keys=True)}`.",
        "", "## Disjointness proof", "",
        "`python3 scripts/validate_dev_disjoint.py` passes and hard-fails on any of the following "
        "cross-set overlaps: exact LLMail attack body, LLMail team ID, benign source body, InjecAgent instruction "
        "versus BIPIA text, Enron email ID (context or carrier), and canary/tracker. "
        "Observed overlap counts: **0 / 0 / 0 / 0 / 0 / 0**. It also checks the evaluation "
        "form requirements: six well-formed emails, recipient rewrite, source and injected "
        "position, token placement and isolation, no context token, owner groups and cap, "
        "internal Enron no-reuse, LLMail 300-word limit, date range and seconds-share, "
        "and clean/benign outcome fields. All pass.", "",
        "## SHA-256", "", "| file | sha256 |", "|---|---|",
    ]
    lines.extend(f"| `data/processed/email_dev/{name}` | `{sha(DEV / name)}` |" for name in names)
    lines += ["", "### Frozen evaluation input hashes", "", "| file | sha256 |", "|---|---|"]
    lines.extend(f"| `data/processed/email/{name}` | `{sha(EVAL / name)}` |"
                 for name in ("attack_inboxes.jsonl", "benign_set.jsonl", "clean_set.jsonl"))
    (DEV / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Wrote", DEV / "REPORT.md")


if __name__ == "__main__":
    main()
