# Dataset-v5 difference proof

Dataset-v5 supersedes dataset-v4 and its first held-out template file; both remain in Git history.

Baseline: `dataset-v3` Git tag. Wrapper source: committed `data/raw/heldout_templates_v2.txt` (SHA-256 `63839ed5030f248a26819208d6b66c69f4d56f63da459ebf63aba957e5259e17`). Seed: `42`. The builder compares baseline and output rows and stops if any unlisted field changes.

- Attack memory inboxes changed: **300/300**; attack `as_is` lines byte-identical: **300/300**.
- Benign memory inboxes changed: **37/37**; benign `as_is` lines byte-identical: **113/113**.
- Non-injected emails inside the 337 changed inboxes structurally identical: **1,685/1,685**.
- `clean_set.jsonl` byte-identical to dataset-v3: SHA-256 `363f3d4b777f7e4fbb410bbf057ac5b99c67cdaffe330a140214e5fff600a022`.
- Each changed inbox has the same item metadata, position, canary/tracker, subject, sender, recipient, date, and all other email fields. Only the indexed email body wrapper changed; the payload bytes were preserved.
- The 37 benign source bodies and their recorded `memory_template` fields changed to match; all other benign source and specification fields are identical.

Benign template choices use the seed among held-out templates that satisfy the existing per-item word-count bound. Attack choices use the seed among all ten. The v4 per-item RNG namespace is retained, so selection indices are comparable where eligibility sets match. No gate output or evaluation result influenced selection.

| File | dataset-v3 SHA-256 | dataset-v5 SHA-256 |
|---|---|---|
| `attack_inboxes.jsonl` | `767662919651bc6e0f858b754c2619d1cc61961ecdaf4ac4f5407c9ad28e328c` | `55db2760ef502172166e1a75be957d02b5d99935b182cae7041b38319c45d9a0` |
| `benign_set.jsonl` | `56175cddae41c7978bc57b48691622b82e693e2b358e1c23b039e7ae9f2b76ac` | `89de97a0ada51bb2152e0b209428bbd28b392ea2dc2ac9a618fa8acf6b3fc41a` |
| `benign_emails.jsonl` | `840697ddbcae23d40650a464caffc8e5c8acd55df3d498048aa18095387246f1` | `3a0019f0af08ebae3f75312ddaf11eee2341252994c4bfaf41a14a0472993079` |
| `benign_emails_v2.jsonl` | `51254a208e68e134a82f01438bf320ae40cb09bd8bd58be52325d594abd108dc` | `dff6e4671348bc552faf354b79c2d9e428adad8300cf6ce28eae1e6297ddb33c` |
| `benign_specs.jsonl` | `03f5058a578e4800e5868995b661626c0bf463bde64e90d81bf4631bf626638f` | `e7e0981f6d9af1b32f0530dd0bf4324e4577ba2650cba9876f1c202faaca029a` |
| `benign_specs_v2.jsonl` | `82355cef010365fb17c8b8e24f38274b6380f6cb97d5e1c3aaf9912a9b373310` | `ca3d279d11ea84f103b3ea7b6fb1814893698cf3c3197afe72ee1780f273f4bf` |
| `clean_set.jsonl` | `363f3d4b777f7e4fbb410bbf057ac5b99c67cdaffe330a140214e5fff600a022` | `363f3d4b777f7e4fbb410bbf057ac5b99c67cdaffe330a140214e5fff600a022` |

Template selection counts (1–10 in the order of the held-out file):

| Template | Attack memory | Benign memory |
|---:|---:|---:|
| 1 | 32 | 6 |
| 2 | 29 | 3 |
| 3 | 38 | 5 |
| 4 | 25 | 2 |
| 5 | 26 | 1 |
| 6 | 30 | 0 |
| 7 | 23 | 8 |
| 8 | 42 | 3 |
| 9 | 24 | 4 |
| 10 | 31 | 5 |
