"""Preflight and extract only evaluation benign060..benign149 for every model."""

import json
import subprocess
import sys
import time
from pathlib import Path

from .dataset import REPO_ROOT
from .extract import load_config, load_existing, load_items, path_from_config
from .overnight import atomic_json, build_summary, now, unload
from .preflight import run_preflight


def main() -> None:
    config = load_config("eval")
    all_items = load_items(config, smoke=False)
    if len(all_items) != 1050 or len({item["item_id"] for _, item in all_items}) != 1050:
        raise RuntimeError("Dataset v2 must contain exactly 1,050 unique items")
    new_ids = {f"benign{i:03d}" for i in range(60, 150)}
    if {item["item_id"] for name, item in all_items if name == "benign"} != {
        f"benign{i:03d}" for i in range(150)
    }:
        raise RuntimeError("Benign IDs are incomplete")
    output_dir = path_from_config(config, "output_dir") / "extract"
    manifest_path = output_dir / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    v1_commit = manifest.get("dataset_versions", [{}])[0].get("commit", manifest.get("commit"))
    if not v1_commit:
        raise RuntimeError("Original evaluation commit is missing from manifest")
    if "dataset_versions" not in manifest:
        manifest["dataset_versions"] = [{"tag": "dataset-v1", "commit": v1_commit,
                                         "dataset_hashes": manifest["dataset_hashes"],
                                         "start_time": manifest["start_time"],
                                         "end_time": manifest["end_time"]}]
    version = next((v for v in manifest["dataset_versions"] if v["tag"] == "dataset-v2"), None)
    if version is None:
        version = {"tag": "dataset-v2", "commit": None, "start_time": now(),
                   "end_time": None, "models": {}}
        manifest["dataset_versions"].append(version)
    parts = []
    for model in config["ollama"]["models"]:
        started = time.monotonic()
        status = "FAILED"
        print(f"Starting v2 additions for {model} at {now()}", flush=True)
        try:
            info = run_preflight(model, config, "eval")
            if version["commit"] and version["commit"] != info["commit"]:
                raise RuntimeError("dataset-v2 commit changed during extraction")
            if version.get("dataset_hashes") and version["dataset_hashes"] != info["dataset_hashes"]:
                raise RuntimeError("dataset-v2 hashes changed during extraction")
            if manifest["extractor_prompt_sha256"] != info["extractor_prompt_sha256"]:
                raise RuntimeError("Extractor prompt differs from dataset-v1 run")
            if manifest["config"] != info["config"]:
                raise RuntimeError("Harness config differs from dataset-v1 run")
            version.update({"commit": info["commit"], "dataset_hashes": info["dataset_hashes"],
                            "extractor_prompt_sha256": info["extractor_prompt_sha256"]})
            version["models"][model] = {"digest": info["digest"], "start_time": now(),
                                          "status": "RUNNING", "end_time": None}
            atomic_json(manifest_path, manifest)
            print(f"Preflight PASSED for {model}; digest {info['digest']}", flush=True)
            subprocess.run([sys.executable, "-u", "-m", "harness.extract", "--model", model,
                            "--benign-v2-only"], cwd=REPO_ROOT, check=True)
            rows = load_existing(output_dir / f"{model}.jsonl", model)
            if not new_ids <= rows.keys():
                raise RuntimeError(f"Only {len(new_ids & rows.keys())}/90 new benign results recorded")
            status = "COMPLETE"
        except Exception as error:
            print(f"FAILED {model}: {type(error).__name__}: {error}", flush=True)
            version["models"].setdefault(model, {"digest": None, "start_time": now()})["error"] = str(error)
        finally:
            try:
                unload(model, config["ollama"]["base_url"])
            except Exception as error:
                print(f"Unload warning for {model}: {error}", flush=True)
            model_version = version["models"][model]
            model_version.update({"status": status, "end_time": now(),
                                  "seconds": time.monotonic() - started})
            manifest["commit"] = version.get("commit") or v1_commit
            if version.get("dataset_hashes"):
                manifest["dataset_hashes"] = version["dataset_hashes"]
            atomic_json(manifest_path, manifest)
            rows = load_existing(output_dir / f"{model}.jsonl", model)
            v1_times = manifest["models"].get(model, {})
            # Summary total time is the accumulated model run time over both releases.
            try:
                from datetime import datetime
                old_seconds = (datetime.fromisoformat(v1_times["end_time"]) -
                               datetime.fromisoformat(v1_times["start_time"])).total_seconds()
            except (KeyError, TypeError, ValueError):
                old_seconds = 0.0
            parts.append(build_summary(model, rows, all_items, status,
                                       old_seconds + model_version["seconds"],
                                       manifest["commit"], manifest["extractor_prompt_sha256"]))
            (output_dir / "SUMMARY.md").write_text(
                "# Evaluation extraction summary (dataset-v2)\n\n"
                f"Dataset commits: `dataset-v1` `{v1_commit}`; `dataset-v2` `{version.get('commit')}`.\n\n"
                + "\n\n".join(parts) + "\n", encoding="utf-8")
    version["end_time"] = now()
    manifest["end_time"] = version["end_time"]
    atomic_json(manifest_path, manifest)


if __name__ == "__main__":
    main()
