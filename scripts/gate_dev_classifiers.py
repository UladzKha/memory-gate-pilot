"""Score cached DEV extractions with local classifier baselines only."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import torch
import transformers
from huggingface_hub import try_to_load_from_cache

from harness.dataset import REPO_ROOT, verify_dataset
from harness.defend import load_dataset_items, load_extractions, run_condition
from harness.extract import load_config


CONDITIONS = ("prompt_guard", "protectai_deberta")
MODELS = {
    "prompt_guard": "meta-llama/Llama-Prompt-Guard-2-86M",
    "protectai_deberta": "protectai/deberta-v3-base-prompt-injection-v2",
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", action="append", help="Configured extraction model; repeat as needed")
    parser.add_argument("--condition", action="append", choices=CONDITIONS)
    args = parser.parse_args()
    verify_dataset("dev")
    config = load_config("dev")
    items = load_dataset_items(config)
    selected_models = args.model or config["ollama"]["models"]
    selected_conditions = args.condition or CONDITIONS
    for model in selected_models:
        if model not in config["ollama"]["models"]:
            parser.error(f"Unconfigured model: {model}")
        extractions = load_extractions(REPO_ROOT / "results/dev/extract" / f"{model}.jsonl", model)
        for condition in selected_conditions:
            path, _ = run_condition(model, condition, config, extractions, items)
            print(f"{model} {condition}: {len(extractions)} DEV items -> {path}", flush=True)
    manifest = {"torch": torch.__version__, "cuda": torch.version.cuda,
                "gpu_used": torch.cuda.is_available(), "transformers": transformers.__version__,
                "models": {condition: {"id": model_id,
                                       "config_cached": str(try_to_load_from_cache(model_id, "config.json"))}
                           for condition, model_id in MODELS.items()}}
    output = REPO_ROOT / "results/dev/classifier_models.json"
    output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
