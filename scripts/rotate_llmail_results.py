#!/usr/bin/env python3
"""Archive old LLMail result rows, preserving all other rows verbatim."""

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODELS = ("qwen3.8:27b", "gemma4:31b", "mistral-small3.2:24b")


def commit(tag):
    return subprocess.check_output(["git", "rev-list", "-n", "1", tag],
                                   cwd=ROOT, text=True).strip()


def main():
    v1 = commit("dataset-v1")
    v2 = commit("dataset-v2")
    dev1 = commit("dev-v1")
    for dataset, folder, expected in (("eval", ROOT / "results/extract", 300),
                                      ("dev", ROOT / "results/dev/extract", 200)):
        archive = folder / "superseded"
        archive.mkdir(exist_ok=True)
        manifest_path = folder / "MANIFEST.json"
        manifest = json.loads(manifest_path.read_text())
        record_commits = manifest.setdefault("record_commits", {})
        archived_commits = manifest.setdefault("superseded_record_commits", {})
        for model in MODELS:
            path = folder / f"{model}.jsonl"
            archived = archive / f"{model}.jsonl"
            if archived.exists():
                raise RuntimeError(f"Archive already exists: {archived}")
            lines = path.read_bytes().splitlines(keepends=True)
            old, kept = [], []
            current_map, old_map = {}, {}
            for line in lines:
                row = json.loads(line)
                item_id = row["item_id"]
                if "llmail" in item_id:
                    old.append(line)
                    old_map[item_id] = v1 if dataset == "eval" else dev1
                else:
                    kept.append(line)
                    current_map[item_id] = (v2 if dataset == "eval" and
                                            item_id.startswith("benign") and
                                            int(item_id[6:]) >= 60 else
                                            v1 if dataset == "eval" else dev1)
            if len(old) != expected or len({json.loads(line)["item_id"] for line in old}) != expected:
                raise RuntimeError(f"Unexpected LLMail result count in {path}: {len(old)}")
            archived.write_bytes(b"".join(old))
            path.write_bytes(b"".join(kept))
            record_commits[model] = current_map
            archived_commits[model] = old_map
            print(f"{dataset} {model}: archived {len(old)}, retained {len(kept)}")
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
