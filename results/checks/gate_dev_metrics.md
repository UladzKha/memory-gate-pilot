# Memory-write gate development evaluation

All inputs are from `results/dev/extract/` and `data/processed/email_dev/`.

| Model | Attack canary before | After allow-only | Attack notes block / quarantine | Benign tracker allow / quarantine / block | Clean inboxes any intervention | Clean note block / quarantine |
|---|---:|---:|---:|---:|---:|---:|
| gemma4:31b | 131/400 | 20/400 | 44 / 124 | 46 / 11 / 0 (43 without tracker) | 6/100 | 0/468 / 8/468 |
| mistral-small3.2:24b | 238/400 | 32/400 | 96 / 222 | 39 / 9 / 0 (52 without tracker) | 13/100 | 0/701 / 14/701 |
| qwen3.8:27b | 42/400 | 5/400 | 29 / 106 | 67 / 21 / 0 (12 without tracker) | 25/100 | 0/670 / 28/670 |

## gemma4:31b rule hits

| Set | T1 | T2 | T3 | N3 | N1 | N2 |
|---|---:|---:|---:|---:|---:|---:|
| attack | 12 | 21 | 3 | 20 | 128 | 44 |
| benign | 0 | 0 | 0 | 0 | 16 | 0 |
| clean | 0 | 0 | 0 | 0 | 8 | 0 |


## mistral-small3.2:24b rule hits

| Set | T1 | T2 | T3 | N3 | N1 | N2 |
|---|---:|---:|---:|---:|---:|---:|
| attack | 45 | 50 | 10 | 13 | 256 | 60 |
| benign | 0 | 0 | 0 | 0 | 19 | 0 |
| clean | 0 | 0 | 0 | 0 | 14 | 0 |


## qwen3.8:27b rule hits

| Set | T1 | T2 | T3 | N3 | N1 | N2 |
|---|---:|---:|---:|---:|---:|---:|
| attack | 15 | 17 | 2 | 2 | 115 | 14 |
| benign | 0 | 0 | 0 | 0 | 41 | 1 |
| clean | 0 | 0 | 0 | 0 | 28 | 0 |
