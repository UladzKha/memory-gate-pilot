# Dataset-v4 difference proof

Baseline: `dataset-v3` Git tag. Wrapper source: committed `data/raw/heldout_templates.txt` (SHA-256 `2140b31d450efa9c6d98017c77c3d89e9f9f92919b28f6404a994b205ec7ba4c`). Seed: `42`. The builder compares baseline and output rows and stops if any unlisted field changes.

- Attack memory inboxes changed: **300/300**; attack `as_is` lines byte-identical: **300/300**.
- Benign memory inboxes changed: **37/37**; benign `as_is` lines byte-identical: **113/113**.
- Non-injected emails inside the 337 changed inboxes structurally identical: **1,685/1,685**.
- `clean_set.jsonl` byte-identical to dataset-v3: SHA-256 `363f3d4b777f7e4fbb410bbf057ac5b99c67cdaffe330a140214e5fff600a022`.
- Each changed inbox has the same item metadata, position, canary/tracker, subject, sender, recipient, date, and all other email fields. Only the indexed email body wrapper changed; the payload bytes were preserved.
- The 37 benign source bodies and their recorded `memory_template` fields changed to match; all other benign source and specification fields are identical.

Benign template choices use the seed among held-out templates that satisfy the existing per-item word-count bound. Attack choices use the seed among all ten. No gate output or evaluation result influenced selection.

| File | dataset-v3 SHA-256 | dataset-v4 SHA-256 |
|---|---|---|
| `attack_inboxes.jsonl` | `767662919651bc6e0f858b754c2619d1cc61961ecdaf4ac4f5407c9ad28e328c` | `c4c519dd3c8b0bb9aef8a0c9935e270d4791f2fab08d8313cfc8569e34723b26` |
| `benign_set.jsonl` | `56175cddae41c7978bc57b48691622b82e693e2b358e1c23b039e7ae9f2b76ac` | `8ce8e1ccad4616a2cb2196e417773413dc1818c9fe430cde1371fa53f53bae67` |
| `benign_emails.jsonl` | `840697ddbcae23d40650a464caffc8e5c8acd55df3d498048aa18095387246f1` | `cca7555b2bad010911ba8af023512d731928c0870140760ac1030fd189c49980` |
| `benign_emails_v2.jsonl` | `51254a208e68e134a82f01438bf320ae40cb09bd8bd58be52325d594abd108dc` | `0dfcafe512957e420c7dccaa3524ba02b196e4ea7db5c07f71a2c54cd2e13a77` |
| `benign_specs.jsonl` | `03f5058a578e4800e5868995b661626c0bf463bde64e90d81bf4631bf626638f` | `6679d3a3baf7ec586269a4cf6b7498e3f427653e2ae24c522b510ba77100e4fc` |
| `benign_specs_v2.jsonl` | `82355cef010365fb17c8b8e24f38274b6380f6cb97d5e1c3aaf9912a9b373310` | `1a584bcd5db328548b61b6fae5751f55bf1bd94132688dd316a5965a37dc3aab` |
| `clean_set.jsonl` | `363f3d4b777f7e4fbb410bbf057ac5b99c67cdaffe330a140214e5fff600a022` | `363f3d4b777f7e4fbb410bbf057ac5b99c67cdaffe330a140214e5fff600a022` |

Template selection counts (1–10 in the order of the held-out file):

| Template | Attack memory | Benign memory |
|---:|---:|---:|
| 1 | 32 | 6 |
| 2 | 29 | 4 |
| 3 | 38 | 2 |
| 4 | 25 | 3 |
| 5 | 26 | 1 |
| 6 | 30 | 0 |
| 7 | 23 | 11 |
| 8 | 42 | 2 |
| 9 | 24 | 1 |
| 10 | 31 | 7 |
