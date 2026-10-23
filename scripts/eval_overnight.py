"""Resume the pre-registered evaluation after oathgate verifies the freeze."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

from harness.dataset import REPO_ROOT
from harness.extract import load_config
from harness.l3_eval import verify_memgate_pin


def check_prereg(oathgate: str) -> None:
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip()
    tag = subprocess.check_output(["git", "rev-list", "-n", "1", "prereg-v1"],
                                  cwd=REPO_ROOT, text=True).strip()
    if head != tag:
        raise RuntimeError("Checkout must be the prereg-v1 commit before the evaluation run")
    subprocess.run([oathgate, "check", "--spec", str(REPO_ROOT / "oathgate.toml")],
                   cwd=REPO_ROOT, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oathgate", required=True, help="Pinned oathgate 0.1.0 executable")
    args = parser.parse_args()
    check_prereg(args.oathgate)
    config = load_config("eval")
    verify_memgate_pin(config)
    env = dict(os.environ, HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1")
    for model in config["ollama"]["models"]:
        for other in config["ollama"]["models"]:
            if other != model:
                subprocess.run(["ollama", "stop", other], check=False)
        subprocess.run([sys.executable, "-m", "scripts.gate_eval_classifiers", "--model", model],
                       cwd=REPO_ROOT, env=env, check=True)
        subprocess.run([sys.executable, "-m", "harness.l3_eval", "--model", model],
                       cwd=REPO_ROOT, env=env, check=True)
        subprocess.run(["ollama", "stop", model], check=False)
    subprocess.run([sys.executable, "-m", "scripts.gate_eval_report"],
                   cwd=REPO_ROOT, env=env, check=True)
    subprocess.run([args.oathgate, "check", "--spec", str(REPO_ROOT / "oathgate.toml")],
                   cwd=REPO_ROOT, check=True)


if __name__ == "__main__":
    main()
