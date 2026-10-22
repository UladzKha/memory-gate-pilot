# Memory-write gate development evaluation

All inputs are from `results/dev/extract/` and `data/processed/email_dev/`.

| Model | Attack canary before | After allow-only | Attack notes block / quarantine | Benign tracker allow / quarantine / block | Clean inboxes any intervention | Clean note block / quarantine |
|---|---:|---:|---:|---:|---:|---:|
| gemma4:31b | 131/400 | 20/400 | 44 / 174 | 46 / 11 / 0 (43 without tracker) | 17/100 | 0/468 / 20/468 |
| mistral-small3.2:24b | 238/400 | 32/400 | 96 / 323 | 39 / 9 / 0 (52 without tracker) | 31/100 | 0/701 / 35/701 |
| qwen3.8:27b | 42/400 | 5/400 | 29 / 149 | 67 / 21 / 0 (12 without tracker) | 40/100 | 0/670 / 48/670 |

## gemma4:31b rule hits

| Set | T1 | T2 | T3 | N3 | N1 | N2 |
|---|---:|---:|---:|---:|---:|---:|
| attack | 12 | 21 | 3 | 20 | 178 | 44 |
| benign | 0 | 0 | 0 | 0 | 24 | 0 |
| clean | 0 | 0 | 0 | 0 | 20 | 0 |


## mistral-small3.2:24b rule hits

| Set | T1 | T2 | T3 | N3 | N1 | N2 |
|---|---:|---:|---:|---:|---:|---:|
| attack | 45 | 50 | 10 | 13 | 357 | 60 |
| benign | 0 | 0 | 0 | 0 | 45 | 0 |
| clean | 0 | 0 | 0 | 0 | 35 | 0 |


## qwen3.8:27b rule hits

| Set | T1 | T2 | T3 | N3 | N1 | N2 |
|---|---:|---:|---:|---:|---:|---:|
| attack | 15 | 17 | 2 | 2 | 158 | 14 |
| benign | 0 | 0 | 0 | 0 | 66 | 1 |
| clean | 0 | 0 | 0 | 0 | 48 | 0 |
