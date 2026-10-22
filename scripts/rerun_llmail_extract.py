#!/usr/bin/env python3
"""Preflight and rerun archived LLMail rows for all configured models."""

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from harness.extract import load_config, load_items, path_from_config  # noqa: E402
from harness.overnight import atomic_json, now, unload  # noqa: E402
from harness.preflight import run_preflight  # noqa: E402


def run_dataset(dataset):
    cfg = load_config(dataset)
    out = path_from_config(cfg, "output_dir") / "extract"
    manifest_path = out / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text())
    ids = {r["item_id"] for name, r in load_items(cfg, smoke=False)
           if name == "attack" and r["source"] == "llmail"}
    expected = 300 if dataset == "eval" else 200
    assert len(ids) == expected
    for model in cfg["ollama"]["models"]:
        print(f"{dataset} {model}: preflight", flush=True)
        info = run_preflight(model, cfg, dataset)
        if info["extractor_prompt_sha256"] != manifest["extractor_prompt_sha256"]:
            raise RuntimeError("Extractor prompt changed")
        if info["config"] != manifest["config"]:
            raise RuntimeError("Extractor config changed")
        if info["digest"] != manifest["models"][model]["digest"]:
            raise RuntimeError("Model digest changed")
        path = out / f"{model}.jsonl"
        old = out / "superseded" / f"{model}.jsonl"
        archived = {json.loads(line)["item_id"] for line in old.read_text().splitlines()}
        if archived != ids:
            raise RuntimeError(f"Incomplete superseded archive: {old}")
        start = time.monotonic()
        status = "FAILED"
        try:
            subprocess.run([sys.executable, "-u", "-m", "harness.extract", "--model", model,
                            "--dataset", dataset, "--llmail-only"], cwd=ROOT, check=True)
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            new_ids = [r["item_id"] for r in rows if r["item_id"] in ids]
            if len(new_ids) != expected or len(set(new_ids)) != expected:
                raise RuntimeError(f"Incomplete new LLMail results: {len(new_ids)}/{expected}")
            commit = info["commit"]
            manifest["record_commits"][model].update({item_id: commit for item_id in ids})
            status = "COMPLETE"
        finally:
            try:
                unload(model, cfg["ollama"]["base_url"])
            except Exception as error:
                print(f"Unload warning: {error}", flush=True)
            manifest.setdefault("llmail_rerun", {})[model] = {
                "status": status, "commit": info["commit"], "digest": info["digest"],
                "dataset_hashes": info["dataset_hashes"], "preflight_at": info["preflight_at"],
                "completed_at": now(), "seconds": round(time.monotonic() - start, 1),
                "items": expected,
            }
            atomic_json(manifest_path, manifest)
        if status != "COMPLETE":
            raise RuntimeError(f"{dataset} {model} rerun failed")
    manifest["current_dataset_commit"] = info["commit"]
    manifest["current_dataset_hashes"] = info["dataset_hashes"]
    atomic_json(manifest_path, manifest)


if __name__ == "__main__":
    for name in ("eval", "dev"):
        run_dataset(name)
