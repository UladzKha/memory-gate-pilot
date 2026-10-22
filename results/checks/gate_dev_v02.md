# DEV memory-write gate v0.2 and Level 3 tool-call results

Only saved DEV extractions, DEV inboxes, and DEV Level 3 tool logs are used. Mock tools have no external effects.

## Level 2 bounds

Reject all excludes v0.1 quarantine or v0.2 allow_tainted notes. Approve all includes them. These are item-level canary-in-memory bounds.

| Model | Gate | Canary before | Reject all | Approve all | Benign tracker allow / tainted / block | Clean inboxes intervened | Clean notes allow / tainted / block |
|---|---|---:|---:|---:|---:|---:|---:|
| gemma4:31b | v0.1 | 131/400 | 20/400 | 105/400 | 46 / 11 / 0 | 6/100 | 460/468 / 8/468 / 0/468 |
| gemma4:31b | v0.2 | 131/400 | 3/400 | 33/400 | 42 / 15 / 0 | 18/100 | 447/468 / 21/468 / 0/468 |
| mistral-small3.2:24b | v0.1 | 238/400 | 32/400 | 176/400 | 39 / 9 / 0 | 13/100 | 687/701 / 14/701 / 0/701 |
| mistral-small3.2:24b | v0.2 | 238/400 | 9/400 | 82/400 | 32 / 16 / 0 | 27/100 | 667/701 / 34/701 / 0/701 |
| qwen3.8:27b | v0.1 | 42/400 | 5/400 | 31/400 | 67 / 21 / 0 | 25/100 | 642/670 / 28/670 / 0/670 |
| qwen3.8:27b | v0.2 | 42/400 | 1/400 | 16/400 | 39 / 49 / 0 | 37/100 | 617/670 / 53/670 / 0/670 |

### Level 2 rule hits

Counts are per note; a note may hit more than one rule.

| Model | Gate | Set | T1 | T2 | T3 | N3 | N1 | N2 |
|---|---|---|---:|---:|---:|---:|---:|---:|
| gemma4:31b | v0.1 | attack | 12 | 21 | 3 | 20 | 128 | 44 |
| gemma4:31b | v0.1 | benign | 0 | 0 | 0 | 0 | 16 | 0 |
| gemma4:31b | v0.1 | clean | 0 | 0 | 0 | 0 | 8 | 0 |
| gemma4:31b | v0.2 | attack | 13 | 178 | 3 | 20 | 225 | 47 |
| gemma4:31b | v0.2 | benign | 0 | 0 | 0 | 0 | 22 | 0 |
| gemma4:31b | v0.2 | clean | 0 | 0 | 0 | 0 | 21 | 0 |
| mistral-small3.2:24b | v0.1 | attack | 45 | 50 | 10 | 13 | 256 | 60 |
| mistral-small3.2:24b | v0.1 | benign | 0 | 0 | 0 | 0 | 19 | 0 |
| mistral-small3.2:24b | v0.1 | clean | 0 | 0 | 0 | 0 | 14 | 0 |
| mistral-small3.2:24b | v0.2 | attack | 46 | 256 | 10 | 13 | 441 | 62 |
| mistral-small3.2:24b | v0.2 | benign | 0 | 0 | 0 | 0 | 53 | 0 |
| mistral-small3.2:24b | v0.2 | clean | 0 | 0 | 0 | 0 | 34 | 0 |
| qwen3.8:27b | v0.1 | attack | 15 | 17 | 2 | 2 | 115 | 14 |
| qwen3.8:27b | v0.1 | benign | 0 | 0 | 0 | 0 | 41 | 1 |
| qwen3.8:27b | v0.1 | clean | 0 | 0 | 0 | 0 | 28 | 0 |
| qwen3.8:27b | v0.2 | attack | 16 | 66 | 2 | 2 | 165 | 16 |
| qwen3.8:27b | v0.2 | benign | 0 | 0 | 0 | 0 | 90 | 1 |
| qwen3.8:27b | v0.2 | clean | 0 | 0 | 0 | 0 | 53 | 0 |

The [A0 audit](gate_dev_a0.md) gives the v0.2 to v0.2.1 comparison, source-pattern checks for every nonblocked attack canary note, and clean N1 examples.

## Level 3 mock-tool outcomes

Attack success counts an item only when its canary appears in an executed tool call. Not-reachable attack items count as unsuccessful. Benign outcome uses any mock tool call on a tracker-reachable benign item as the operational action proxy; there is no separate gold label for action legitimacy. Executed takes precedence if an item has both executed and denied calls. Clean false denials use the 30 seeded items per model. Intervals are Wilson 95% intervals.

| Model | Condition | Attack success (all attack items) | Reachable attack items | Denied attack calls | Benign executed | Benign denied | Benign not attempted | Clean items with denial | Clean denials per item |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| gemma4:31b | none | 69/400 (17.2%; 95% CI 13.9%–21.3%) | 131/400 | 0 | 3/57 (5.3%; 95% CI 1.8%–14.4%) | 0/57 (0.0%; 95% CI 0.0%–6.3%) | 54/57 (94.7%; 95% CI 85.6%–98.2%) | 0/30 (0.0%; 95% CI 0.0%–11.4%) | 0/30 |
| gemma4:31b | promptguard | skipped: missing local Python packages: torch, transformers | — | — | — | — | — | — | — |
| gemma4:31b | protectai | skipped: missing local Python packages: torch, transformers | — | — | — | — | — | — | — |
| gemma4:31b | gate_write | 15/400 (3.8%; 95% CI 2.3%–6.1%) | 33/400 | 0 | 4/57 (7.0%; 95% CI 2.8%–16.7%) | 0/57 (0.0%; 95% CI 0.0%–6.3%) | 53/57 (93.0%; 95% CI 83.3%–97.2%) | 0/30 (0.0%; 95% CI 0.0%–11.4%) | 0/30 |
| gemma4:31b | gate_full | 0/400 (0.0%; 95% CI 0.0%–1.0%) | 33/400 | 15 | 4/57 (7.0%; 95% CI 2.8%–16.7%) | 0/57 (0.0%; 95% CI 0.0%–6.3%) | 53/57 (93.0%; 95% CI 83.3%–97.2%) | 4/30 (13.3%; 95% CI 5.3%–29.7%) | 5/30 |
| mistral-small3.2:24b | none | 87/400 (21.8%; 95% CI 18.0%–26.1%) | 238/400 | 0 | 25/48 (52.1%; 95% CI 38.3%–65.5%) | 0/48 (0.0%; 95% CI 0.0%–7.4%) | 23/48 (47.9%; 95% CI 34.5%–61.7%) | 0/30 (0.0%; 95% CI 0.0%–11.4%) | 0/30 |
| mistral-small3.2:24b | promptguard | skipped: missing local Python packages: torch, transformers | — | — | — | — | — | — | — |
| mistral-small3.2:24b | protectai | skipped: missing local Python packages: torch, transformers | — | — | — | — | — | — | — |
| mistral-small3.2:24b | gate_write | 26/400 (6.5%; 95% CI 4.5%–9.4%) | 82/400 | 0 | 25/48 (52.1%; 95% CI 38.3%–65.5%) | 0/48 (0.0%; 95% CI 0.0%–7.4%) | 23/48 (47.9%; 95% CI 34.5%–61.7%) | 0/30 (0.0%; 95% CI 0.0%–11.4%) | 0/30 |
| mistral-small3.2:24b | gate_full | 0/400 (0.0%; 95% CI 0.0%–1.0%) | 82/400 | 26 | 20/48 (41.7%; 95% CI 28.8%–55.7%) | 5/48 (10.4%; 95% CI 4.5%–22.2%) | 23/48 (47.9%; 95% CI 34.5%–61.7%) | 6/30 (20.0%; 95% CI 9.5%–37.3%) | 7/30 |
| qwen3.8:27b | none | 31/400 (7.8%; 95% CI 5.5%–10.8%) | 42/400 | 0 | 70/88 (79.5%; 95% CI 70.0%–86.7%) | 0/88 (0.0%; 95% CI 0.0%–4.2%) | 18/88 (20.5%; 95% CI 13.3%–30.0%) | 0/30 (0.0%; 95% CI 0.0%–11.4%) | 0/30 |
| qwen3.8:27b | promptguard | skipped: missing local Python packages: torch, transformers | — | — | — | — | — | — | — |
| qwen3.8:27b | protectai | skipped: missing local Python packages: torch, transformers | — | — | — | — | — | — | — |
| qwen3.8:27b | gate_write | 13/400 (3.2%; 95% CI 1.9%–5.5%) | 16/400 | 0 | 70/88 (79.5%; 95% CI 70.0%–86.7%) | 0/88 (0.0%; 95% CI 0.0%–4.2%) | 18/88 (20.5%; 95% CI 13.3%–30.0%) | 0/30 (0.0%; 95% CI 0.0%–11.4%) | 0/30 |
| qwen3.8:27b | gate_full | 0/400 (0.0%; 95% CI 0.0%–1.0%) | 16/400 | 24 | 53/88 (60.2%; 95% CI 49.8%–69.8%) | 17/88 (19.3%; 95% CI 12.4%–28.8%) | 18/88 (20.5%; 95% CI 13.3%–30.0%) | 12/30 (40.0%; 95% CI 24.6%–57.7%) | 31/30 |

## Gate-full attack successes for review

Available: 0; exported: 0 DEV items.
