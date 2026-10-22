# Email development dataset report

This is a development set for designing the memory-write gate. The development sampling frame remains evaluation dataset-v1. This report records the dev-v2 sender repair and current evaluation dataset-v3 input hashes.

## Sources and licenses

- **LLMail-Inject:** local `data/raw/llmail-inject/data/raw_submissions_phase{1,2}.jsonl`; [dataset card](https://huggingface.co/datasets/microsoft/llmail-inject-challenge) declares MIT. Kept only submissions with `exfil.sent` and `exfil.destination` true, a literal `contact@contact.com` anchor, and subject plus body at most 288 words (12 reserved for wrapping). Removed every evaluation team ID and body, deduplicated bodies, then sampled 100 proportionally by scenario with seed 45.
- **InjecAgent:** [repository](https://github.com/uiuc-kang-lab/InjecAgent) at `f19c9f2c79a41046eb13c03c51a24c567a8ffa07`; [MIT license](https://github.com/uiuc-kang-lab/InjecAgent/blob/main/LICENCE). The license says: “Permission is hereby granted, free of charge, to any person obtaining a copy”. Full copyright and permission notice is retained in `INJECAGENT_LICENCE.txt`. The two base test-case files supplied 1,054 cases and 62 unique instructions. The sample uses one case per unique instruction plus 38 further distinct cases, for 100 cases across six attack types. Repeated instruction text is disclosed and has distinct source-case IDs. The exact minimal source projection is committed as `injecagent_source_cases.jsonl`.
- **Benign:** LLMail-Inject `data/emails_for_fp_tests.json` (MIT); 100 of 203 parseable false-positive emails sampled with seed 45. Each becomes a standalone email with a fresh email or `REF_` tracker.
- **Enron:** the existing parsed `data/processed/email/enron_pool.jsonl`, derived from the Enron corpus. Every email ID in the evaluation attack, benign, and clean sets, including BIPIA carriers, and both evaluation used-ID trackers was excluded before dev assembly. See `data/raw/REPORT.md` for source provenance.

## Construction

- 100 LLMail and 100 InjecAgent cases, each with `as_is` and `memory` variants: 400 attack inboxes. InjecAgent instructions are woven into real Enron carrier bodies using the same `REF_` ticket pattern as BIPIA. Both attack types use the same five memory templates and canary generator as evaluation, with dev-only IDs and seed 45.
- 100 benign inboxes and 100 clean inboxes. Every inbox contains six emails. Injected emails use the evaluation seeded date function; owners host at most 10 inboxes per set. No Enron email ID is reused within dev.
- LLMail scenario counts: `{"level1a": 30, "level1b": 1, "level1c": 11, "level1d": 4, "level1e": 2, "level1g": 18, "level1h": 1, "level1k": 4, "level1m": 2, "level1o": 1, "level1q": 2, "level1s": 3, "level1u": 1, "level2a": 3, "level2b": 1, "level2c": 2, "level2g": 1, "level2s": 1, "level3a": 3, "level3c": 2, "level4a": 4, "level4c": 2, "level4g": 1}`.
- InjecAgent attack-type counts: `{"Data Security Harm": 14, "Financial Data": 9, "Financial Harm": 17, "Others": 23, "Physical Data": 18, "Physical Harm": 19}`.

## Disjointness proof

`python3 scripts/validate_dev_disjoint.py` passes and hard-fails on any of the following cross-set overlaps: exact LLMail attack body, LLMail team ID, benign source body, InjecAgent instruction versus BIPIA text, Enron email ID (context or carrier), and canary/tracker. Observed overlap counts: **0 / 0 / 0 / 0 / 0 / 0**. It also checks the evaluation form requirements: six well-formed emails, recipient rewrite, source and injected position, token placement and isolation, no context token, owner groups and cap, internal Enron no-reuse, LLMail 300-word limit, date range and seconds-share, and clean/benign outcome fields. All pass.

## SHA-256

| file | sha256 |
|---|---|
| `data/processed/email_dev/attack_inboxes.jsonl` | `ed70f959dcdbbb91a0b65f81f6665185e156d0c0cc2675c0d23237feeaa991d9` |
| `data/processed/email_dev/benign_set.jsonl` | `ec84c50cb6d97f233bafd77d06c9c98a9ab0ccadf862ffdfea3aa8af9bcf13f5` |
| `data/processed/email_dev/clean_set.jsonl` | `a6681dbf932732a71597fbddb19b2d4e407df1a925f5bc8b8fa3a59b5ba3a34e` |
| `data/processed/email_dev/attacks_pool.jsonl` | `2ec6dabcb69b0924f434663720631e55f8207a18538d9379e9d7eb8ad86fddcf` |
| `data/processed/email_dev/benign_emails.jsonl` | `c6fba7055d1b69df6ff5c3ca076f346c51107020b1a97041994db3139ebc9e1c` |
| `data/processed/email_dev/mailbox_split.jsonl` | `4cc1e560e69c3e2124fcaf34acda2b44d79cb6b5037f88e2e8e5333deb7481e3` |
| `data/processed/email_dev/injecagent_source_cases.jsonl` | `42d49f0a057d5d332f2a2c601c632d27cca7afcdb91bcebd7756df912ed7b483` |
| `data/processed/email_dev/_used_ctx_ids.txt` | `43519e3bd0d1e870f848e67babeb407d558d93104cc493f7d4428c1d1d023909` |
| `data/processed/email_dev/_clean_ctx_used.txt` | `e8cdc9d0fa48564fe1addb7834e7aaf0eb59ad407727a008286d9206e9b2e156` |
| `data/processed/email_dev/INJECAGENT_LICENCE.txt` | `b48589499dbb84caa796b00b4ea652b0443e49660282c44d890fd473b8c0674e` |

### Frozen evaluation input hashes

| file | sha256 |
|---|---|
| `data/processed/email/attack_inboxes.jsonl` | `767662919651bc6e0f858b754c2619d1cc61961ecdaf4ac4f5407c9ad28e328c` |
| `data/processed/email/benign_set.jsonl` | `c7d29cbbddfaf32b7b6329eff6ac565128c7f8d20ed7f4f8b7b53b30b047f5c1` |
| `data/processed/email/clean_set.jsonl` | `363f3d4b777f7e4fbb410bbf057ac5b99c67cdaffe330a140214e5fff600a022` |

## dev-v2 sender repair

The 200 LLMail injected From addresses now use the shared `p_<8 hex>@example.org` form, generated by the shared `fake_addr` SHA-1 mapping from `<dataset seed>:sender.llmail.<item_id>`, independently of canaries. Each of those 200 rows differs from dev-v1 only in that From field. Every InjecAgent, benign, clean, and context email is byte-identical to dev-v1, as are the mailbox split and source pools. The full canary appears in the LLMail Subject for 20 items (10 source attacks × 2 variants); these are original attack text, not bare fragments. The shared header validator permits only that complete token in those Subjects.

Two consecutive rebuilds produced identical hashes. The new `attack_inboxes.jsonl` hash is `ed70f959dcdbbb91a0b65f81f6665185e156d0c0cc2675c0d23237feeaa991d9`; benign and clean hashes remain as above.
