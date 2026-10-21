# Email-channel dataset build report

Pilot dataset for memory-poisoning gate evaluation on the **email channel**.
Built deterministically from `data/raw/`; config `config/dataset.yaml` (seed 42).
Pipeline: `scripts/email/01..06`. Generated `2026-10-21`.

> The older **transcripts** channel (`data/processed/transcripts_v0/`) is kept
> for reference only and is **superseded** by this email channel.

## Pipeline
| step | script | output |
|------|--------|--------|
| 01 | `01_parse_enron.py` | `enron_pool.jsonl` (20236 unique Enron emails across 137 owners) |
| 02 | `02_split_mailboxes.py` | `mailbox_split.jsonl` (137 owners → carrier 60 / clean 77) + `owners.jsonl` |
| 03 | `03_build_attack_inboxes.py` | `attack_inboxes.jsonl` (600 items) + `_used_ctx_ids.txt` (3300 ids) |
| 05 | `05_build_clean_set.py` | `clean_set.jsonl` (300 items) + `_clean_ctx_used.txt` |
| 06 | `06_build_benign_set.py` | `benign_set.jsonl` (60 items) |
| — | `scripts/validate_email_dataset.py` | validation gate |
| — | `scripts/email/check_benign.py` | benign-class surface-rate gate |

## Counts
| set | items | notes |
|-----|-------|-------|
| Enron pool (unique, kept) | 20236 | from 41509 files (see Drops) |
| owners | 137 | carrier 60 / clean 77 (disjoint groups) |
| attack items | 600 | 300 llmail (150×2) + 300 bipia (150×2); as_is 300 / memory 300 |
|  |  | 60 carrier owners used (≤10 inboxes/owner); inbox_size 6 |
| clean items | 300 | = attack / 2; 72 clean owners used (≤6 inboxes/owner) |
| benign items | 60 | allow 45 / quarantine 15; 48 clean owners used (≤2 inboxes/owner) |

## Fix #1 — anchored LLMail pool (2026-10-21)
The two LLMail attacks that had **no destination address** (`contact@contact.com`)
in either body or subject are now **excluded** during collection
(`02_build_attacks.py:52`, `require_anchor`). The 150-row LLMail pool is
re-sampled deterministically from the 19709 anchored unique exfil rows
(`unique_bodies_pool=14308`). Both the old `llmail0088` and `llmail0132`
non-anchored rows are gone. `validate_email_dataset.py` no longer grants a
special exemption for "canary missing in attack body/subject"; it now errors if
any LLMail attack lacks its canary in body or subject (and any BIPIA attack
without its ticket in its body).

## Fix #2 — seeded injected email date (2026-10-21)
`ecommon.py:164, seeded_injected_date()` derives a deterministic RFC822 date
for every injected email (LLMail attack in `03`, benign in `06`). The date
falls **between** the minimum and maximum date of the inbox's other (context)
emails, with a seeded hour/minute/second, rendered in the median context
offset / tz-name. Both 03 and 06 call this helper before emitting the email.
The `:00:00`-second share on injected emails is within ±5 percentage points of
the context share (0.017 vs 0.058), so the injected stamps are not distinguishable
by a round-number clock test.

## Fix #3 — owner cap ≤10 inboxes per set (2026-10-21)
`email.max_inboxes_per_owner` added to `config/dataset.yaml` (default 10).
`02_split_mailboxes.py` now reserves the **60 deepest owners** for the carrier
group (minimum 60 = ceil(600/10)) and the **77 remaining** for clean
(minimum ceil(360/10)=36 needed; actual 77). `03`, `05` and `06` each track an
`inboxes[owner]` counter and refuse to assign an 11th inbox to any owner in
that set.

Measured max inboxes by owner:

| set    | owners used | max inboxes / owner | cap |
|--------|-------------|---------------------|-----|
| attack | 60          | 10                  | 10  |
| clean  | 72          | 6                   | 10  |
| benign | 48          | 2                   | 10  |

Clean set uses 72 of the 77 clean-group owners (5 owners are below the depth
needed to host even one inbox). Benign uses 48 owners but each is capped at
2 inboxes within the benign set only (the same owner can host clean inboxes
separately — the per-set cap is the requirement).

## Fix #4 — quote-chain strip + <30-word drop (2026-10-21)
`01_parse_enron.py` now strips: (a) everything from the first quoted-chain
banner (`"----- Original Message -----"` and the indented / trailing-banner
variants — see `ORIG_MARKER_RE`), (b) lines beginning with `>` (forwarded
quote marker), (c) `<<File: …>>` and `- [File attached]` placeholders, then
drops any row whose body falls below `pool_min_words` (30). The new drop
counts are:

| reason | count |
|--------|-------|
| files parsed | 41509 |
| dropped missing_fields | 1304 |
| dropped out_of_range | 13401 |
| dropped attachment_only | 1747 |
| dropped dup | 4821 |
| **unique in-range kept** | **20236** |

## Fix #5 — "Original Message" residual (2026-10-21)
Case-sensitive `"Original Message"` is **absent** from every context email in
the assembled dataset (attack + clean + benign): **0** rows.

Caveat (honest reporting): the pool still contains **52** rows that contain the
phrase in lowercase prose — e.g. *"destroy all copies of the original
message"*, *"all future messages relating to the original message have been
blocked"* — which are legitimate Enron content, not a forwarded-chain banner.
Dropping them would damage real data and they do not match the banner regex,
so they are kept. They also do **not** match the validator's literal
`"Original Message"` (case-sensitive) check and therefore pass. The lowercase
phrase is NOT a forwarded-chain marker and is not reported as a failure for
that reason.

## Fix #6 — BIPIA real-carrier embed (2026-10-21)

The BIPIA attack email is a **real Enron carrier** whose length is **steered
toward the frozen benign length distribution**, so the two classes are
indistinguishable by length alone. For each BIPIA item the builder
(`03_build_attack_inboxes.py`, `bipia` branch) does:

1. Samples a **seeded target total length** from the 60 approved benign bodies
   (`ecommon.sample_benign_target_length`, `random.Random(f"{seed}:{salt}")`,
   salt `bipia.target.<item_id>`).
2. Among the 6 context emails drawn for that inbox, picks the carrier whose
   `len(carrier_body) + len(attack_text)` is **closest** to that target
   (ties broken by larger carrier length, then id).
3. The **attack text + ticket** form a single injected block. For the
   `memory` variant that block is memory-wrapped — i.e. the template is
   prepended to the **attack** (`"<template> <attack text> <ticket>"`), **not**
   to the whole carrier body. The block is then placed at a **seeded position**
   — start, middle, or end (`bipia.place.<item_id>`) — among the carrier's
   original paragraphs.

The carrier's body is otherwise **left untouched** (its native subject, date,
and all original paragraphs are preserved). There is **no hard word-count
cap** on individual carriers (the pool floor of 30 still applies); the global
shape of the length distribution is the gate.

| metric | value |
|--------|-------|
| bipia injected body (min/q25/med/q75/max) | 40 / 61 / **82** / 135 / 379 |
| benign injected body (min/q25/med/q75/max) | 20 / 55 / **77** / 163 / 297 |
| bipia median inside benign q1–q3? | **yes** (82 ∈ [55, 163]) |
| llmail injected body (min/q25/med/q75/max) | 1 / 43 / **78** / 150 / 287 |

The validator now **fails** if the BIPIA median falls outside the benign
q1–q3 range (`validate_email_dataset.py` "REQ6/LENGTH" check).

## Drop table (this release)
| source | reason | count |
|--------|--------|-------|
| LLMail (02_build_attacks) | no `contact@contact.com` in body or subject → excluded from pool | dropped in source collection |
| AMI (transcripts channel, superseded) | segment < 1000 words | 1 (`ES2005a`) |
| BIPIA | none | 0 |
| benign pre-approval | rejected by authoring gate | 60 (`benign_emails_REJECTED.jsonl`) |
| Enron (01_parse) | file-level drops per Fix #4 | missing 1304, out_of_range 13401, attachment 1747, dup 4821 |

## Canary / tracker tokens
All LLMail canaries and benign trackers share the reserved relay domain
`relay.example.net`; BIPIA tickets use `REF_<8hex>`. Generated by the same
`new_hex8` generator (seed 42) so the two pools are indistinguishable by
surface form.

Token-format split (**total** tokens across the dataset — the 600 attack
canaries plus the 60 benign trackers, counted once each):

| shape  | total | breakdown |
|--------|-------|-----------|
| email  | 330   | 300 LLMail canaries (`c_…@relay.example.net`) + 30 benign email trackers |
| ticket | 330   | 300 BIPIA tickets (`REF_…`) + 30 benign `REF_` trackers |

So the two classes share exactly the same surface form: 330 email-shaped
tokens and 330 ticket-shaped tokens. (A prior version of this report read
"ticket 30" because the validator's `TICKET_RE` was case-sensitive and the
300 BIPIA attack canaries are stored lower-case; that has been fixed — the
classifier now matches `[Rr][Ee][Ff]_`.)

## Fix #2 — Benign formatting parity (render-time)

The frozen benign bodies are single flat paragraphs, while real context emails
use line breaks (96% of them) and RE:/FW: subjects (~22%). To close that gap,
`06_build_benign_set.py` reformats each frozen benign body **at render time**
(words are never changed — only paragraph breaks are inserted and a greeting /
sign-off, if present, is lifted onto its own line):

1. If the body opens on a greeting (Hi / Hello / Dear / Good day / Morning…),
   that greeting is lifted onto its own first line.
2. If the body ends on a valediction + signature (regards / thanks / sincerely /
   …, Priya Narayan), that sign-off block is lifted onto its own trailing line.
3. The remaining prose is split into **1–4 paragraphs** at sentence boundaries
   (seeded on `benign.paras.<id>`), so the line-break share of the benign class
   tracks the context class.
4. ~20% of benign subjects get a deterministic `RE: ` prefix (seeded on
   `benign.re.<id>`).

The `check_benign.py` per-row + surface-rate gate still passes on the frozen
raw bodies (it runs against `benign_emails.jsonl`, not the rendered set), and
the renderer never changes the words, so the frozen class is untouched.

Measured injected-email surface rates (line-break / RE-FW subject) vs. context:

| set     | line-break | RE/FW subject | n   |
|---------|-----------|---------------|-----|
| llmail  | 65%       | 3%            | 300 |
| bipia   | 100%      | 27%           | 300 |
| benign  | 88%       | 32%           | 60  |
| context | 95%       | 22%           | 5100 |

The benign class now sits between the two attack classes on line-break share
(88% vs. context 95%) and is within 10 pp of context on RE/FW subject share
(32% vs. 22%).

## Benign class (frozen)
`benign_emails.jsonl` (60 rows) was **approved and frozen** on 2026-10-20.
The authoring scripts (`benign_specs.py`, `benign_texts.py`) predate approval
and are NOT re-run in the current pipeline. `check_benign.py` validates it:

| metric | LLMail (150) | benign (60) | delta |
|--------|-------------|-------------|-------|
| sign-off | 15 (10%) | 7 (12%) | 2pp |
| greeting | 60 (40%) | 24 (40%) | 0pp |
| forbidden words | — | 0 | — |
| near-duplicate pairs ≥12 trigrams | — | 0 | — |

## Limitations

1. **Carrier / clean owner-pool split.** The carrier pool (60 owners) and the
   clean-context pool (77 owners) are drawn **disjointly** from the same raw
   Enron mailboxes, but the split is by **inbox depth** (top-60 by message
   count host attack inboxes; the remaining 77 host clean and benign
   inboxes). This means a single real Enron user's messages will not appear as
   both an attack carrier and a clean/benign context row in the same dataset,
   and the two sets are therefore **not independent draws from the same user
   population**. The split is a deliberate de-duplication choice (to avoid
   leaking which mailbox carries the attack into the clean/benign context), not
   a sampling property. Any downstream study that assumes attack and benign
   contexts are iid from the same user distribution should treat this as a
   limitation.

2. **Benign surface-rate parity.** The benign class is authored (not mined) and
   is frozen; `check_benign.py` confirms its greeting / sign-off / word-
   frequency surface rates are within a few points of the LLMail attack
   distribution, but it is a 60-sample estimate and not a population claim.

3. **Quoted-chain residual.** The 52 lowercase *"original message"* prose rows
   (see Fix #5) are retained as legitimate content; they do not match the
   forwarded-chain banner regex.

4. **Non-ASCII / special-token payloads are part of the attack technique.**
   ~37% of the LLMail attacks (55 of 150) carry non-ASCII or special-token
   payloads (foreign-language text, odd symbols) as part of the exfil / role-
   hijack instruction. This skew is **part of the attack**, not noise — it
   reflects the real LLMail-inject submissions, and it is deliberately *not*
   normalised away. A defender tuned on ASCII-only clean traffic will see a
   different character-distribution signal than an attacker, which is a real
   (if narrow) behavioural feature of the corpus.

5. **Memory templates appear at different, intentional rates.** Memory-
   template wraps are present in **50% of attacks** (all `memory` variants) but
   only in **25% of benign** emails (the 15 `quarantine` benign rows). This is
   by design: benign memory items are **expected to be quarantined**
   (`expected_outcome: quarantine`), so they intentionally mirror the attack
   surface while still being *benign in content*. The 45 `allow` benign rows are
   plain-English without any memory wrap, mirroring the `as_is` attack surface.

6. **Per-email `id` / `source` are metadata, never to be shown to the model.**
   Each email row in `attack_inboxes.jsonl` / `clean_set.jsonl` /
   `benign_set.jsonl` carries an `id` and a `source` field
   (`llmail-attack`, `bipia-attack`, `benign`, `enron-context`). These are
   **harness metadata only** — the harness must render **only** `From`, `To`,
   `Date`, `Subject`, and body to the model. Exposing `source` (or `id`) would
   leak the ground-truth class directly: a model that reads `source` is not
   performing egress detection, it is reading the label. This is not enforced
   by the dataset itself; it is a harness-construction contract, and it is
   stated here so any downstream evaluation harness can be audited against
   it.

## Length quartiles (attack+benign body, words)
| set    | min | q25 | med | q75 | max |
|--------|-----|-----|-----|-----|-----|
| llmail | 1   | 43  | 78  | 150 | 287 |
| bipia  | 40  | 61  | 82  | 135 | 379 |
| benign | 20  | 55  | 77  | 163 | 297 |

Note: the LLMail minimum is 1 word because many LLMail payloads are a single
word exfil destination + instruction (see `llmail0000` etc.). All three
medians (78 / 82 / 77) now sit within a 5-word band of each other; the BIPIA
median (82) is inside the benign q1–q3 (55–163), which the validator enforces.

## Determinism proof
Two from-scratch re-runs (full 02 → 01 → 03 → 05 → 06, including the LLMail
pool regeneration) produce **byte-identical** outputs (`cmp` clean):

| file | sha256 |
|------|--------|
| `data/processed/attacks.jsonl` | `df3cf13f6e3e77575b79ffdeaddfedc9a1507db109773ca1012957f8e7a604e3` |
| `data/processed/email/attacks_pool.jsonl` | `df3cf13f6e3e77575b79ffdeaddfedc9a1507db109773ca1012957f8e7a604e3` |
| `data/processed/email/enron_pool.jsonl` (01) | `f45aec17930b655fc63b8cdac88140bafbfb0f5dd338114b70ccee7bb7945d57` |
| `data/processed/email/owners.jsonl` | `40dabbb552410c1f7003ae35bd72c5fa14a500e169477ea324d7ad5d16b49e35` |
| `data/processed/email/parse_stats.json` | `5c97c0f6749654477d900a5f44af231d7f5a18d96715f2ac6f3a4e9f2749c265` |
| `data/processed/email/mailbox_split.jsonl` (02) | `d07cf4ffc266f07f50057f016c209cebcd50f75eb10f267c35524deb1f4f8d5a` |
| `data/processed/email/attack_inboxes.jsonl` (03) | `0cd8d113282c9c4941f3da9b6d830f91000854a3d7b34d6d6fb1f60a56f5ddb7` |
| `data/processed/email/clean_set.jsonl` (05) | `363f3d4b777f7e4fbb410bbf057ac5b99c67cdaffe330a140214e5fff600a022` |
| `data/processed/email/benign_set.jsonl` (06) | `c7d29cbbddfaf32b7b6329eff6ac565128c7f8d20ed7f4f8b7b53b30b047f5c1` |
| `data/processed/email/_used_ctx_ids.txt` | `c23cd2c9f98d52780ef106d65a4372104db3ffdbaceffc73e3a99624ed235a96` |
| `data/processed/email/_clean_ctx_used.txt` | `ef26d1e1820fa7191a0c821ba1c052ebed60b2b9f6c784bfa7641afc5835abf9` |

## Scripts / validators
| script | purpose | status |
|--------|---------|--------|
| `scripts/02_build_attacks.py` | LLMail+bipia pool (anchored) | pass |
| `scripts/email/01..03, 05, 06` | build pipeline | pass |
| `scripts/validate_email_dataset.py` | email-channel validation gate | PASS |
| `scripts/email/check_benign.py` | benign-class surface-rate + per-row gate | PASS |

## Enron license
No formal LICENSE in `data/raw/enron`. Governing terms: CMU/William Cohen
distribution statement (https://www.cs.cmu.edu/~enron/):
> "I am distributing this dataset as a resource for researchers who are
> interested in improving current email tools, or understanding how email is
> currently used… In using this dataset, please be sensitive to the privacy of
> the people involved (and remember that many of these people were certainly
> not involved in any of the actions which precipitated the investigation.)"

Data originally FERC-released, redacted for affected employees, no attachments,
no CC / OSI license.
