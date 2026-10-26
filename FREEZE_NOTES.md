# Freeze notes

This file records how to check the oathgate locks. It does not change `DEVIATIONS.md` or any frozen file.

`oathgate check` hashes the spec plus every file the spec names. The lock stores one ruler hash, not a per-file hash. Exit 0 and the line `ok <hash>` mean the working tree matches that lock.

## v1

| Item | Value |
|---|---|
| Spec | `oathgate.toml` |
| Lock | `oathgate.lock` |
| Ruler hash | `0436ede7fa1ab9b1e9ae9bb5290e57f4e39136b2ed3bd49229f31d77cc2d5e65` |
| Frozen at | `2026-10-23T08:25:49+00:00` |
| Tag | `prereg-v1` = `2807454e97487e7d6f41b393f2e22f68273269c8` |

The lock history also has an earlier ruler, `4a61d51d828e2a286f67b8491775b777569c14339f605621cae42e1cae7722d2`, frozen at `2026-10-23T08:25:02+00:00` and superseded at `2026-10-23T08:25:49+00:00`. The hash to check is the current one in the table.

The v1 pin of the gate library is memgate `v0.2.0`, commit `a348c0bf612a22b2d623196dcc8a2c080cc9e09c`, as written in `harness/config/harness.yaml` at `prereg-v1`.

## v2

| Item | Value |
|---|---|
| Spec | `oathgate_v2.toml` |
| Lock | `oathgate_v2.lock` |
| Ruler hash | `d11d5dc9def78c3bb48f122d61a6e8c49a21aa79bf799c463050a986212b8c76` |
| Frozen at | `2026-10-24T06:34:24+00:00` |
| Tag | `prereg-v2` = `1992905c9cabf7780439c442c6e194b65cdaab24` |

On `main` at the time of these notes, `oathgate check --spec oathgate_v2.toml --lock oathgate_v2.lock` prints `ok` and the hash above. The v2 pin is memgate `v0.3.0`, commit `ff89e4a3d52302e6e0922240c97cebb12e615b4f`.

## Why v1 fails on main

v2 reused paths that v1 also hashes. These four files differ between `prereg-v1` and `main`:

- `data/processed/email/attack_inboxes.jsonl`
- `data/processed/email/benign_set.jsonl`
- `harness/config/harness.yaml`
- `harness/dataset.py`

`oathgate.toml`, `oathgate.lock`, `PREREG.md`, and `DEVIATIONS.md` are the same on `main` as at `prereg-v1`.

A check on `main` with the files currently on disk does not match. Expected `0436ede7fa1ab9b1e9ae9bb5290e57f4e39136b2ed3bd49229f31d77cc2d5e65`. Actual `a507b89f649f64ddd0e7a1bda059f2a8108f0c393806546c4c1d8f29062e6650`.

The memgate copy on disk is `v0.3.0`. Its `gate.py` is not the v1 bytes. SHA-256 of `memgate/src/memgate/gate.py` on disk is `36bb60895f1439d630b89d34fba25b82c4884efa41525e1ea1c1a6d999d0d357`. The same path at memgate `a348c0b` is `f2ffa3c467c58242acf694dc379050f26b26435cab23f3c22f6cbf3a64393f5d`. `__init__.py`, `guard.py`, and `memory.py` have the same SHA-256 at both commits.

## How to verify v1

Check v1 at the tag, not on `main`.

```sh
git worktree add ../mgp-prereg-v1 prereg-v1
cd ../mgp-prereg-v1
mkdir -p results/extract memgate/src/memgate
# The four results/extract files are gitignored. Link the copies from the main checkout.
# Then put memgate v0.2.0 sources in memgate/src/memgate/.
# From the memgate clone: git show a348c0bf612a22b2d623196dcc8a2c080cc9e09c:src/memgate/<file>
oathgate check --spec oathgate.toml --lock oathgate.lock
```

That command was run on 2026-10-26. With the tag's tracked files, the on-disk `results/extract/` files, and memgate `v0.2.0` sources, it printed `ok 0436ede7fa1ab9b1e9ae9bb5290e57f4e39136b2ed3bd49229f31d77cc2d5e65`.

The same tag with the on-disk memgate `v0.3.0` sources failed. Expected the v1 hash. Actual `c1335673088187b69e9532a6db920e9c42414fef01e6036d0c0ea269048c737d`. The only change between those two checks was the four memgate modules. Three of them already matched `v0.2.0`. So the on-disk extract files still match the v1 ruler, and `gate.py` does not.

v1 also hashes `results/extract/MANIFEST.json`, which is gitignored and is not in the v2 spec. The passing check used the on-disk file. Its SHA-256 is `8739b807b7f7cc6755408f98a3b1daa3373f62f4b03ea90d9c0a16f9f0d2ce39`.

Remove the worktree when finished: `git worktree remove ../mgp-prereg-v1`.

## Frozen paths that are not in git

`.gitignore` ignores `results/` and `memgate/`. These 18 paths are in `oathgate_v2.toml` and are not in this git repo. They are on disk. SHA-256 is of the local file on 2026-10-26. The same bytes are in `frozen-artifacts-v2.tar.gz` (not committed).

| Path | SHA-256 |
|---|---|
| `results/extract/gemma4:31b.jsonl` | `f6f04ccb5a95fd5aae6f9798b9c7debadc84d8e6aa0fa507e423e84c8c77df65` |
| `results/extract/mistral-small3.2:24b.jsonl` | `392bc9f545679003de77b3eda1aa91546b654eac5fff9521fc4ea2033d2f5ad6` |
| `results/extract/qwen3.8:27b.jsonl` | `47201b80b31adf527bf09ce730c40d04fcbb61d737acdb37c405e6f0b7574826` |
| `results/v2/extract_v5/gemma4:31b.jsonl` | `221eef0c712164861ca5455dae89b73b50c760a623e0fffc68362d4973f5e6b2` |
| `results/v2/extract_v5/mistral-small3.2:24b.jsonl` | `c5f8f0fcdf45171c8b86ed8548817b67352bc412514ddbd03fc4dcb4769ed898` |
| `results/v2/extract_v5/qwen3.8:27b.jsonl` | `434fdad776610c3ac5dd375826d03d41b94780db7d7b2d525df6a45cb9a1afca` |
| `results/v2/extract_input_v5/gemma4:31b__promptguard_input.jsonl` | `29e4e791b745747cae42ffa4fd96cbd75c21ad91aa6c7ad6dbceb6c535a753f4` |
| `results/v2/extract_input_v5/gemma4:31b__protectai_input.jsonl` | `dd0f30e3d78c8a2de48061a1ce1bfc42b580eeccceb9833f3f22bd77e2484ddd` |
| `results/v2/extract_input_v5/mistral-small3.2:24b__promptguard_input.jsonl` | `36ae2b33a8a55d60aa0aef2c40449ef1cd5381569c878185f782c718232497d2` |
| `results/v2/extract_input_v5/mistral-small3.2:24b__protectai_input.jsonl` | `0946491788aca67ee653410dac85c1d102905f31a61184eb999a22b087a088b7` |
| `results/v2/extract_input_v5/qwen3.8:27b__promptguard_input.jsonl` | `3fff363d6aa4315dcd631f70bd48416e946502447b7123cb1cc01e5edac6575d` |
| `results/v2/extract_input_v5/qwen3.8:27b__protectai_input.jsonl` | `5b4328e0bdbb65e049854139a6939896c3d1549cde9e8a22e7514fd03ef87256` |
| `results/v2/input_scores_v5/promptguard_input.json` | `5bc6b71bc3401fbff8831fd6dc5d078a2400eeb051859643555e8e4d3b1d8275` |
| `results/v2/input_scores_v5/protectai_input.json` | `84471f4a8f5f54f668b4b5bc76a7cadbe55e4d12c93daa8812ad79f1442898b0` |
| `memgate/src/memgate/__init__.py` | `1bcde37fa37cabd2e7a65f3d93501a08c270a73ec51803422d6f8778fb63a540` |
| `memgate/src/memgate/gate.py` | `36bb60895f1439d630b89d34fba25b82c4884efa41525e1ea1c1a6d999d0d357` |
| `memgate/src/memgate/guard.py` | `66c68d96fb03f77b6495f9a2f1d4ddd633252d2c2253eb70ae515a58ac8829ab` |
| `memgate/src/memgate/memory.py` | `384e9cc6d0dd0b6cfc01b24efb1eabc638e0ab8c351624d0e3409d1aac51dccb` |

## The results report is not inside the hash

`results/checks/eval_v2.md` is the v2 results report. It is tracked. It is not listed in `oathgate_v2.toml`, so the ruler does not cover it.

Commit `e1a29a6f70adae7f680d4785a39b6326a0679ca6` ("Report frozen evaluation v2 results and hypothesis decisions"). SHA-256 `c10a5c7a114d471c4cafc9b1375c2b9fd033d56b0ca14793d6159bca112d9d55`. The file is unchanged from that commit through `3f65382` on `main`.

## Hardcoded oathgate path

`scripts/eval_v2_overnight.py` line 10 sets a Python constant:

```python
OATHGATE = "/home/oops/ai-lab/oathgate/.venv/bin/oathgate"
```

The script does not read an environment variable. Changing `OATHGATE` or `PATH` in the shell does not change this constant. The file is in the v2 ruler, so leave it as written.

To run that script unchanged, put the oathgate 0.1.0 executable at that path. A symlink is enough:

```sh
mkdir -p /home/oops/ai-lab/oathgate/.venv/bin
ln -sfn "$(command -v oathgate)" /home/oops/ai-lab/oathgate/.venv/bin/oathgate
```

That path is specific to the machine where the script was written. To check the freeze on another machine, do not use the overnight script. Run your own binary:

```sh
oathgate check --spec oathgate_v2.toml --lock oathgate_v2.lock
```
