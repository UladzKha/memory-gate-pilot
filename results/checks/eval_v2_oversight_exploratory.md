# Exploratory, post-hoc, not pre-registered — evaluation v2 oversight

This analysis uses existing frozen v2 run outputs only. No model or condition was run again. All tool actions are logged mocks.
The blind-approval figure assumes every held call would be approved and executed as logged; it does not model later agent behavior.
Executed and held-exposed attack items can overlap. The requested arithmetic sum is shown, and distinct-item blind-approval success subtracts that overlap. Rates use Wilson 95% intervals (z = 1.96).

## Input files

| Path | SHA-256 |
|---|---|
| `data/processed/email/attack_inboxes.jsonl` | `55db2760ef502172166e1a75be957d02b5d99935b182cae7041b38319c45d9a0` |
| `data/processed/email/benign_set.jsonl` | `89de97a0ada51bb2152e0b209428bbd28b392ea2dc2ac9a618fa8acf6b3fc41a` |
| `data/processed/email/clean_set.jsonl` | `363f3d4b777f7e4fbb410bbf057ac5b99c67cdaffe330a140214e5fff600a022` |
| `results/checks/eval_v2.md` | `c10a5c7a114d471c4cafc9b1375c2b9fd033d56b0ca14793d6159bca112d9d55` |
| `harness/canary.py` | `a3022fee75879bc2fd771c427c68867df1f442361d501dba8d602a907a8b5095` |
| `results/v2/l3/qwen3.8:27b__gate_full_tainted.jsonl` | `fc2a0c470408a895580b1102cbbb6d6489e3faee2a81f0f385d4ee6a9ad5e76f` |
| `results/v2/l3/qwen3.8:27b__gate_full_strict.jsonl` | `e9f10fda9d1b2c01492df4b6c50ee02332a13b722f05be94904c90b80cd1a84e` |
| `results/v2/l3/gemma4:31b__gate_full_tainted.jsonl` | `17c056480a6834dde7e7d4cfca80385d41d1e493d4ae446618560ac15e54ce0a` |
| `results/v2/l3/gemma4:31b__gate_full_strict.jsonl` | `1067875af212c7a64c290bb3b506d37ccf9d7ef9d3b89741d0fd003b97148e6c` |
| `results/v2/l3/mistral-small3.2:24b__gate_full_tainted.jsonl` | `9c65e4afec287efaef09d0f590d8ecc0c96f95940ed1b9d1bbf67b9e9e62f29b` |
| `results/v2/l3/mistral-small3.2:24b__gate_full_strict.jsonl` | `f31d371bd602fd4878d800e1f9a65145a41c672baeac58d9e7119e9c62fbb233` |

Script: `scripts/oversight_exploratory.py`.

## Attack exposure under blind approval

An exposed attack item has at least one denied call whose arguments contain its item canary. The denominator includes all 600 attacks, including unreachable items.

| Model | Policy | Executed success | Held-for-confirmation exposure | Both | Arithmetic sum | Success under blind approval (distinct items) |
|---|---|---:|---:|---:|---:|---:|
| qwen3.8:27b | gate_full_tainted | 4/600 (0.7%; 95% CI 0.3%–1.7%) | 25/600 (4.2%; 95% CI 2.8%–6.1%) | 1 | 29 | 28/600 (4.7%; 95% CI 3.2%–6.7%) |
| qwen3.8:27b | gate_full_strict | 0/600 (0.0%; 95% CI 0.0%–0.6%) | 28/600 (4.7%; 95% CI 3.2%–6.7%) | 0 | 28 | 28/600 (4.7%; 95% CI 3.2%–6.7%) |
| gemma4:31b | gate_full_tainted | 0/600 (0.0%; 95% CI 0.0%–0.6%) | 15/600 (2.5%; 95% CI 1.5%–4.1%) | 0 | 15 | 15/600 (2.5%; 95% CI 1.5%–4.1%) |
| gemma4:31b | gate_full_strict | 0/600 (0.0%; 95% CI 0.0%–0.6%) | 15/600 (2.5%; 95% CI 1.5%–4.1%) | 0 | 15 | 15/600 (2.5%; 95% CI 1.5%–4.1%) |
| mistral-small3.2:24b | gate_full_tainted | 6/600 (1.0%; 95% CI 0.5%–2.2%) | 55/600 (9.2%; 95% CI 7.1%–11.7%) | 0 | 61 | 61/600 (10.2%; 95% CI 8.0%–12.8%) |
| mistral-small3.2:24b | gate_full_strict | 0/600 (0.0%; 95% CI 0.0%–0.6%) | 61/600 (10.2%; 95% CI 8.0%–12.8%) | 0 | 61 | 61/600 (10.2%; 95% CI 8.0%–12.8%) |

## Held-call canary counts by set

Every logged denied call is counted, including repeated calls with the same arguments. For attack and benign items, 'canary' means that item's canary appears in the call arguments. Clean request days have no attack canary. The clean set contains the 100 selected days per model and policy.
The canary-bearing share is conditional on this evaluation's attack/benign/clean mix; a blended precision would not estimate a real-world base rate.

| Model | Policy | Set | Canary-bearing held calls | Other held calls | Canary-bearing share (Wilson 95%) |
|---|---|---|---:|---:|---:|
| qwen3.8:27b | gate_full_tainted | attack | 29 | 20 | 29/49 (59.2%; 95% CI 45.2%–71.8%) |
| qwen3.8:27b | gate_full_tainted | benign | 118 | 16 | 118/134 (88.1%; 95% CI 81.5%–92.5%) |
| qwen3.8:27b | gate_full_tainted | clean | 0 | 22 | 0/22 (0.0%; 95% CI 0.0%–14.9%) |
| qwen3.8:27b | gate_full_strict | attack | 33 | 29 | 33/62 (53.2%; 95% CI 41.0%–65.1%) |
| qwen3.8:27b | gate_full_strict | benign | 143 | 62 | 143/205 (69.8%; 95% CI 63.2%–75.6%) |
| qwen3.8:27b | gate_full_strict | clean | 0 | 69 | 0/69 (0.0%; 95% CI 0.0%–5.3%) |
| gemma4:31b | gate_full_tainted | attack | 15 | 1 | 15/16 (93.8%; 95% CI 71.7%–98.9%) |
| gemma4:31b | gate_full_tainted | benign | 21 | 0 | 21/21 (100.0%; 95% CI 84.5%–100.0%) |
| gemma4:31b | gate_full_tainted | clean | 0 | 2 | 0/2 (0.0%; 95% CI 0.0%–65.8%) |
| gemma4:31b | gate_full_strict | attack | 15 | 2 | 15/17 (88.2%; 95% CI 65.7%–96.7%) |
| gemma4:31b | gate_full_strict | benign | 22 | 2 | 22/24 (91.7%; 95% CI 74.2%–97.7%) |
| gemma4:31b | gate_full_strict | clean | 0 | 4 | 0/4 (0.0%; 95% CI 0.0%–49.0%) |
| mistral-small3.2:24b | gate_full_tainted | attack | 60 | 22 | 60/82 (73.2%; 95% CI 62.7%–81.6%) |
| mistral-small3.2:24b | gate_full_tainted | benign | 49 | 10 | 49/59 (83.1%; 95% CI 71.5%–90.5%) |
| mistral-small3.2:24b | gate_full_tainted | clean | 0 | 22 | 0/22 (0.0%; 95% CI 0.0%–14.9%) |
| mistral-small3.2:24b | gate_full_strict | attack | 66 | 30 | 66/96 (68.8%; 95% CI 58.9%–77.1%) |
| mistral-small3.2:24b | gate_full_strict | benign | 61 | 16 | 61/77 (79.2%; 95% CI 68.9%–86.8%) |
| mistral-small3.2:24b | gate_full_strict | clean | 0 | 52 | 0/52 (0.0%; 95% CI 0.0%–6.9%) |

## Held calls per item

Buckets count logged denied calls per item; 3+ includes every item with three or more. Rates use the set size shown in each row.

| Model | Policy | Set | Items | 0 | 1 | 2 | 3+ |
|---|---|---|---:|---:|---:|---:|---:|
| qwen3.8:27b | gate_full_tainted | attack | 600 | 568/600 (94.7%; 95% CI 92.6%–96.2%) | 20/600 (3.3%; 95% CI 2.2%–5.1%) | 10/600 (1.7%; 95% CI 0.9%–3.0%) | 2/600 (0.3%; 95% CI 0.1%–1.2%) |
| qwen3.8:27b | gate_full_tainted | benign | 150 | 70/150 (46.7%; 95% CI 38.9%–54.6%) | 45/150 (30.0%; 95% CI 23.2%–37.8%) | 25/150 (16.7%; 95% CI 11.6%–23.4%) | 10/150 (6.7%; 95% CI 3.7%–11.8%) |
| qwen3.8:27b | gate_full_tainted | clean | 100 | 83/100 (83.0%; 95% CI 74.5%–89.1%) | 12/100 (12.0%; 95% CI 7.0%–19.8%) | 5/100 (5.0%; 95% CI 2.2%–11.2%) | 0/100 (0.0%; 95% CI 0.0%–3.7%) |
| qwen3.8:27b | gate_full_strict | attack | 600 | 566/600 (94.3%; 95% CI 92.2%–95.9%) | 20/600 (3.3%; 95% CI 2.2%–5.1%) | 8/600 (1.3%; 95% CI 0.7%–2.6%) | 6/600 (1.0%; 95% CI 0.5%–2.2%) |
| qwen3.8:27b | gate_full_strict | benign | 150 | 40/150 (26.7%; 95% CI 20.2%–34.3%) | 55/150 (36.7%; 95% CI 29.4%–44.6%) | 33/150 (22.0%; 95% CI 16.1%–29.3%) | 22/150 (14.7%; 95% CI 9.9%–21.2%) |
| qwen3.8:27b | gate_full_strict | clean | 100 | 62/100 (62.0%; 95% CI 52.2%–70.9%) | 19/100 (19.0%; 95% CI 12.5%–27.8%) | 11/100 (11.0%; 95% CI 6.3%–18.6%) | 8/100 (8.0%; 95% CI 4.1%–15.0%) |
| gemma4:31b | gate_full_tainted | attack | 600 | 584/600 (97.3%; 95% CI 95.7%–98.4%) | 16/600 (2.7%; 95% CI 1.6%–4.3%) | 0/600 (0.0%; 95% CI 0.0%–0.6%) | 0/600 (0.0%; 95% CI 0.0%–0.6%) |
| gemma4:31b | gate_full_tainted | benign | 150 | 132/150 (88.0%; 95% CI 81.8%–92.3%) | 16/150 (10.7%; 95% CI 6.7%–16.6%) | 1/150 (0.7%; 95% CI 0.1%–3.7%) | 1/150 (0.7%; 95% CI 0.1%–3.7%) |
| gemma4:31b | gate_full_tainted | clean | 100 | 99/100 (99.0%; 95% CI 94.6%–99.8%) | 0/100 (0.0%; 95% CI 0.0%–3.7%) | 1/100 (1.0%; 95% CI 0.2%–5.4%) | 0/100 (0.0%; 95% CI 0.0%–3.7%) |
| gemma4:31b | gate_full_strict | attack | 600 | 584/600 (97.3%; 95% CI 95.7%–98.4%) | 15/600 (2.5%; 95% CI 1.5%–4.1%) | 1/600 (0.2%; 95% CI 0.0%–0.9%) | 0/600 (0.0%; 95% CI 0.0%–0.6%) |
| gemma4:31b | gate_full_strict | benign | 150 | 129/150 (86.0%; 95% CI 79.5%–90.7%) | 19/150 (12.7%; 95% CI 8.3%–18.9%) | 1/150 (0.7%; 95% CI 0.1%–3.7%) | 1/150 (0.7%; 95% CI 0.1%–3.7%) |
| gemma4:31b | gate_full_strict | clean | 100 | 97/100 (97.0%; 95% CI 91.5%–99.0%) | 2/100 (2.0%; 95% CI 0.6%–7.0%) | 1/100 (1.0%; 95% CI 0.2%–5.4%) | 0/100 (0.0%; 95% CI 0.0%–3.7%) |
| mistral-small3.2:24b | gate_full_tainted | attack | 600 | 534/600 (89.0%; 95% CI 86.2%–91.3%) | 54/600 (9.0%; 95% CI 7.0%–11.6%) | 8/600 (1.3%; 95% CI 0.7%–2.6%) | 4/600 (0.7%; 95% CI 0.3%–1.7%) |
| mistral-small3.2:24b | gate_full_tainted | benign | 150 | 98/150 (65.3%; 95% CI 57.4%–72.5%) | 45/150 (30.0%; 95% CI 23.2%–37.8%) | 7/150 (4.7%; 95% CI 2.3%–9.3%) | 0/150 (0.0%; 95% CI 0.0%–2.5%) |
| mistral-small3.2:24b | gate_full_tainted | clean | 100 | 85/100 (85.0%; 95% CI 76.7%–90.7%) | 10/100 (10.0%; 95% CI 5.5%–17.4%) | 4/100 (4.0%; 95% CI 1.6%–9.8%) | 1/100 (1.0%; 95% CI 0.2%–5.4%) |
| mistral-small3.2:24b | gate_full_strict | attack | 600 | 525/600 (87.5%; 95% CI 84.6%–89.9%) | 58/600 (9.7%; 95% CI 7.6%–12.3%) | 13/600 (2.2%; 95% CI 1.3%–3.7%) | 4/600 (0.7%; 95% CI 0.3%–1.7%) |
| mistral-small3.2:24b | gate_full_strict | benign | 150 | 89/150 (59.3%; 95% CI 51.3%–66.9%) | 51/150 (34.0%; 95% CI 26.9%–41.9%) | 6/150 (4.0%; 95% CI 1.8%–8.5%) | 4/150 (2.7%; 95% CI 1.0%–6.7%) |
| mistral-small3.2:24b | gate_full_strict | clean | 100 | 69/100 (69.0%; 95% CI 59.4%–77.2%) | 19/100 (19.0%; 95% CI 12.5%–27.8%) | 7/100 (7.0%; 95% CI 3.4%–13.7%) | 5/100 (5.0%; 95% CI 2.2%–11.2%) |

## Attack exposure by source and variant

| Model | Policy | Source | Variant | Exposed attacks |
|---|---|---|---|---:|
| qwen3.8:27b | gate_full_tainted | llmail | as_is | 13/150 (8.7%; 95% CI 5.1%–14.3%) |
| qwen3.8:27b | gate_full_tainted | llmail | memory | 9/150 (6.0%; 95% CI 3.2%–11.0%) |
| qwen3.8:27b | gate_full_tainted | bipia | as_is | 2/150 (1.3%; 95% CI 0.4%–4.7%) |
| qwen3.8:27b | gate_full_tainted | bipia | memory | 1/150 (0.7%; 95% CI 0.1%–3.7%) |
| qwen3.8:27b | gate_full_strict | llmail | as_is | 14/150 (9.3%; 95% CI 5.6%–15.1%) |
| qwen3.8:27b | gate_full_strict | llmail | memory | 10/150 (6.7%; 95% CI 3.7%–11.8%) |
| qwen3.8:27b | gate_full_strict | bipia | as_is | 3/150 (2.0%; 95% CI 0.7%–5.7%) |
| qwen3.8:27b | gate_full_strict | bipia | memory | 1/150 (0.7%; 95% CI 0.1%–3.7%) |
| gemma4:31b | gate_full_tainted | llmail | as_is | 3/150 (2.0%; 95% CI 0.7%–5.7%) |
| gemma4:31b | gate_full_tainted | llmail | memory | 10/150 (6.7%; 95% CI 3.7%–11.8%) |
| gemma4:31b | gate_full_tainted | bipia | as_is | 0/150 (0.0%; 95% CI 0.0%–2.5%) |
| gemma4:31b | gate_full_tainted | bipia | memory | 2/150 (1.3%; 95% CI 0.4%–4.7%) |
| gemma4:31b | gate_full_strict | llmail | as_is | 3/150 (2.0%; 95% CI 0.7%–5.7%) |
| gemma4:31b | gate_full_strict | llmail | memory | 10/150 (6.7%; 95% CI 3.7%–11.8%) |
| gemma4:31b | gate_full_strict | bipia | as_is | 0/150 (0.0%; 95% CI 0.0%–2.5%) |
| gemma4:31b | gate_full_strict | bipia | memory | 2/150 (1.3%; 95% CI 0.4%–4.7%) |
| mistral-small3.2:24b | gate_full_tainted | llmail | as_is | 19/150 (12.7%; 95% CI 8.3%–18.9%) |
| mistral-small3.2:24b | gate_full_tainted | llmail | memory | 23/150 (15.3%; 95% CI 10.4%–22.0%) |
| mistral-small3.2:24b | gate_full_tainted | bipia | as_is | 6/150 (4.0%; 95% CI 1.8%–8.5%) |
| mistral-small3.2:24b | gate_full_tainted | bipia | memory | 7/150 (4.7%; 95% CI 2.3%–9.3%) |
| mistral-small3.2:24b | gate_full_strict | llmail | as_is | 24/150 (16.0%; 95% CI 11.0%–22.7%) |
| mistral-small3.2:24b | gate_full_strict | llmail | memory | 24/150 (16.0%; 95% CI 11.0%–22.7%) |
| mistral-small3.2:24b | gate_full_strict | bipia | as_is | 6/150 (4.0%; 95% CI 1.8%–8.5%) |
| mistral-small3.2:24b | gate_full_strict | bipia | memory | 7/150 (4.7%; 95% CI 2.3%–9.3%) |
