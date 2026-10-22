"""Checks that bind an extraction to frozen inputs and a fully resident model."""

import argparse
import hashlib
import json
import shutil
import subprocess
import urllib.request
from datetime import datetime, timezone

from .dataset import DATASET_FILES, DATASET_DIR, REPO_ROOT, verify_dataset
from .extract import load_config, path_from_config, post_json


def get_json(base_url: str, endpoint: str, timeout: int = 20) -> dict:
    with urllib.request.urlopen(base_url.rstrip("/") + endpoint, timeout=timeout) as response:
        return json.load(response)


def git_identity(dataset: str = "eval") -> str:
    paths = ["harness/", "data/processed/email/"] if dataset == "eval" else [
        "harness/", "scripts/", "data/processed/email_dev/", "data/processed/email/"]
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all", "--", *paths],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    )
    if status.stdout.strip():
        raise RuntimeError("Git tree is dirty in extraction inputs/code:\n" + status.stdout)
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip()


def configured_urls(config: dict) -> list[str]:
    urls = config["ollama"].get("all_base_urls", [config["ollama"]["base_url"]])
    return list(dict.fromkeys([config["ollama"]["base_url"], *urls]))


def loaded_models(config: dict) -> dict:
    state = {}
    for url in configured_urls(config):
        try:
            state[url] = get_json(url, "/api/ps").get("models", [])
        except Exception as error:
            state[url] = f"unreachable: {error}"
    return state


def run_preflight(model: str, config: dict | None = None, dataset: str = "eval") -> dict:
    config = config or load_config(dataset)
    if model not in config["ollama"]["models"]:
        raise ValueError(f"Model is not configured: {model}")
    verify_dataset(dataset)
    if dataset == "dev":
        verify_dataset("eval")
    commit = git_identity(dataset)
    print(f"Preflight commit: {commit}", flush=True)
    free = shutil.disk_usage(REPO_ROOT).free
    if free <= 5_000_000_000:
        raise RuntimeError(f"Free disk space <= 5 GB: {free} bytes")
    url = config["ollama"]["base_url"]
    tags = get_json(url, "/api/tags")
    matching = [entry for entry in tags.get("models", []) if entry.get("name") == model or entry.get("model") == model]
    if len(matching) != 1:
        raise RuntimeError(f"Model tag missing from Ollama at {url}: {model}")
    # A tiny request forces the model to load before checking residency.
    post_json(url, "/api/generate", {"model": model, "prompt": "Hi", "stream": False,
             "options": {"num_predict": 1, "num_ctx": config["ollama"]["num_ctx"]}}, 300)
    ps = get_json(url, "/api/ps")
    loaded = [entry for entry in ps.get("models", []) if entry.get("name") == model or entry.get("model") == model]
    others = {port: [entry for entry in entries if entry.get("name") != model and entry.get("model") != model]
              for port, entries in loaded_models(config).items() if isinstance(entries, list)}
    if any(others.values()):
        raise RuntimeError("Other models loaded on configured Ollama ports: " + json.dumps(others, indent=2))
    if len(loaded) != 1 or loaded[0].get("size_vram") != loaded[0].get("size") or not loaded[0].get("size"):
        state = json.dumps(loaded_models(config), indent=2)
        raise RuntimeError(f"model not fully on GPU: {model}; loaded on configured Ollama ports:\n{state}")
    prompt = path_from_config(config, "prompts_dir") / "extractor_system.txt"
    return {
        "model": model, "digest": matching[0].get("digest"), "commit": commit,
        "dataset_hashes": {name: hashlib.sha256((path_from_config(config, "dataset_dir") / name).read_bytes()).hexdigest() for name in DATASET_FILES},
        "extractor_prompt_sha256": hashlib.sha256(prompt.read_bytes()).hexdigest(),
        "config": config, "preflight_at": datetime.now(timezone.utc).isoformat(),
        "size": loaded[0]["size"], "size_vram": loaded[0]["size_vram"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True)
    parser.add_argument("--dataset", choices=("eval", "dev"), default="eval")
    args = parser.parse_args()
    try:
        result = run_preflight(args.model, dataset=args.dataset)
    except Exception as error:
        parser.exit(1, f"Preflight FAILED for {args.model}: {error}\n")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
