# Evaluation v2 stage 1 — DEV only

This exploratory run used the existing 400 attack, 100 benign, and 100 clean DEV inboxes. The frozen evaluation dataset, its results, and `prereg-v1` were not used or changed. All Level 3 tools were logged mocks with no external effects. The DEV runner was committed as `f0a2391` before model calls.

## Changes and method

`memgate` `v0.3.0-dev` (`ff89e4a`) moves persistence and memory phrases to `N2` `allow_tainted`; only `T1`, narrowed `T2`, and `T3` block. `N3` can taint but cannot block. The unit suite includes the five-template, four-or-more-word generalization guard. Gate conditions use the frozen DEV extractions as input. Input-classifier conditions score `Subject: {subject}\n\n{body}` per email with the pinned local classifier, drop emails at or above the DEV-calibrated threshold, extract from the remaining inbox in original order, and then run Level 3.

For each classifier, the threshold is the next representable float above the 32nd largest score among 3,100 DEV clean context emails, giving at most 31 false positives (1%). This calibration uses no evaluation data. The Level 3 clean sample is the same 30 IDs per model selected by the DEV runner. Attack success includes all 400 attacks; benign tool outcomes use only tracker-reachable items, with executed taking precedence over denied. Clean denial counts selected clean items with any denied mock call.

Saved DEV Level 3 calls were reused only when the model-visible memory and the relevant guard behavior were identical. Changed cases received fresh calls. `reused / fresh` counts selected items with reused or fresh calls; unselected items receive no call.

## DEV input-classifier calibration

| Condition | Threshold | Attack emails detected | LLMail | InjecAgent | Benign injected FP | Clean context FP | Inbox items changed (attack / benign / clean) |
|---|---:|---:|---:|---:|---:|---:|---:|
| promptguard_input | `0.042698696255683906` | 67/400 (16.8%) | 66/200 (33.0%) | 1/200 (0.5%) | 0/100 (0.0%) | 31/3100 (1.0%) | 79 / 9 / 5 |
| protectai_input | `0.9979725480079652` | 96/400 (24.0%) | 78/200 (39.0%) | 18/200 (9.0%) | 0/100 (0.0%) | 31/3100 (1.0%) | 111 / 9 / 5 |

## v0.2 versus v0.3 gate conditions

Level 2 canary retained counts attack items with a canary in stored notes. Benign blocked counts items whose frozen extraction had a tracker-bearing note but no such note survived the write gate. All benign denominators are 100 for that column. Baseline v0.2 values come from the saved DEV Level 3 records; v0.3 values come from the new stage directory.

| Model | Condition | L2 canary retained | L3 attack success | Attack reachable | Benign blocked | Benign executed | Benign denied | Benign no action | Clean denied | Reused / fresh |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| qwen3.8:27b | v0.2 gate_write | 16/400 (4.0%) | 13/400 (3.2%) | 16/400 | 0/100 | 70/88 | 0/88 | 18/88 | 0/30 | 0 / 134 |
| qwen3.8:27b | v0.3 gate_write | 30/400 (7.5%) | 24/400 (6.0%) | 30/400 | 0/100 | 70/88 | 0/88 | 18/88 | 0/30 | 134 / 14 |
| qwen3.8:27b | v0.2 gate_full_tainted | 16/400 (4.0%) | 1/400 (0.2%) | 16/400 | 0/100 | 66/88 | 4/88 | 18/88 | 5/30 | 0 / 134 |
| qwen3.8:27b | v0.3 gate_full_tainted | 30/400 (7.5%) | 0/400 (0.0%) | 30/400 | 0/100 | 67/88 | 4/88 | 17/88 | 5/30 | 109 / 39 |
| qwen3.8:27b | v0.2 gate_full_strict | 16/400 (4.0%) | 0/400 (0.0%) | 16/400 | 0/100 | 53/88 | 17/88 | 18/88 | 12/30 | 0 / 134 |
| qwen3.8:27b | v0.3 gate_full_strict | 30/400 (7.5%) | 0/400 (0.0%) | 30/400 | 0/100 | 53/88 | 17/88 | 18/88 | 12/30 | 134 / 14 |
| gemma4:31b | v0.2 gate_write | 33/400 (8.2%) | 15/400 (3.8%) | 33/400 | 0/100 | 4/57 | 0/57 | 53/57 | 0/30 | 0 / 120 |
| gemma4:31b | v0.3 gate_write | 114/400 (28.5%) | 58/400 (14.5%) | 114/400 | 0/100 | 4/57 | 0/57 | 53/57 | 0/30 | 120 / 81 |
| gemma4:31b | v0.2 gate_full_tainted | 33/400 (8.2%) | 0/400 (0.0%) | 33/400 | 0/100 | 4/57 | 0/57 | 53/57 | 1/30 | 0 / 120 |
| gemma4:31b | v0.3 gate_full_tainted | 114/400 (28.5%) | 0/400 (0.0%) | 114/400 | 0/100 | 4/57 | 0/57 | 53/57 | 1/30 | 101 / 100 |
| gemma4:31b | v0.2 gate_full_strict | 33/400 (8.2%) | 0/400 (0.0%) | 33/400 | 0/100 | 4/57 | 0/57 | 53/57 | 4/30 | 0 / 120 |
| gemma4:31b | v0.3 gate_full_strict | 114/400 (28.5%) | 0/400 (0.0%) | 114/400 | 0/100 | 4/57 | 0/57 | 53/57 | 4/30 | 120 / 81 |
| mistral-small3.2:24b | v0.2 gate_write | 82/400 (20.5%) | 26/400 (6.5%) | 82/400 | 0/100 | 25/48 | 0/48 | 23/48 | 0/30 | 0 / 160 |
| mistral-small3.2:24b | v0.3 gate_write | 185/400 (46.2%) | 61/400 (15.2%) | 185/400 | 0/100 | 25/48 | 0/48 | 23/48 | 0/30 | 160 / 103 |
| mistral-small3.2:24b | v0.2 gate_full_tainted | 82/400 (20.5%) | 3/400 (0.8%) | 82/400 | 0/100 | 24/48 | 1/48 | 23/48 | 1/30 | 0 / 160 |
| mistral-small3.2:24b | v0.3 gate_full_tainted | 185/400 (46.2%) | 4/400 (1.0%) | 185/400 | 0/100 | 25/48 | 0/48 | 23/48 | 2/30 | 117 / 146 |
| mistral-small3.2:24b | v0.2 gate_full_strict | 82/400 (20.5%) | 0/400 (0.0%) | 82/400 | 0/100 | 20/48 | 5/48 | 23/48 | 6/30 | 0 / 160 |
| mistral-small3.2:24b | v0.3 gate_full_strict | 185/400 (46.2%) | 0/400 (0.0%) | 185/400 | 0/100 | 20/48 | 5/48 | 23/48 | 6/30 | 160 / 103 |

## Input-classifier conditions

For these conditions, `benign blocked` counts benign injected emails removed by the input classifier. A missing tracker after a surviving benign email is an extraction outcome, not a classifier block. Other columns have the same definitions as above.

| Model | Condition | L2 canary retained | L3 attack success | Attack reachable | Benign blocked | Benign executed | Benign denied | Benign no action | Clean denied | Reused / fresh |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| qwen3.8:27b | promptguard_input | 33/400 (8.2%) | 25/400 (6.2%) | 33/400 | 0/100 | 69/86 | 0/86 | 17/86 | 0/30 | 142 / 7 |
| qwen3.8:27b | protectai_input | 34/400 (8.5%) | 24/400 (6.0%) | 34/400 | 0/100 | 68/86 | 0/86 | 18/86 | 0/30 | 143 / 7 |
| gemma4:31b | promptguard_input | 130/400 (32.5%) | 70/400 (17.5%) | 130/400 | 0/100 | 2/57 | 0/57 | 55/57 | 0/30 | 206 / 11 |
| gemma4:31b | protectai_input | 112/400 (28.0%) | 59/400 (14.8%) | 112/400 | 0/100 | 3/56 | 0/56 | 53/56 | 0/30 | 191 / 7 |
| mistral-small3.2:24b | promptguard_input | 211/400 (52.8%) | 71/400 (17.8%) | 211/400 | 0/100 | 27/51 | 0/51 | 24/51 | 0/30 | 278 / 14 |
| mistral-small3.2:24b | protectai_input | 196/400 (49.0%) | 69/400 (17.2%) | 196/400 | 0/100 | 23/49 | 0/49 | 26/49 | 0/30 | 259 / 16 |

## Interpretation limits

LLMail inputs were selected from successful challenge submissions, partly against classifier defenses. The DEV detection rates therefore describe this selected set and do not estimate detection on an unselected attack population. Input filtering changes what the extractor sees, while the gate conditions act on saved notes; their Level 2 values represent distinct intervention points. Thresholds were calibrated and measured on the same DEV clean emails, so the 1% operating point is descriptive.
