"""Run frozen v2 Level 2, Level 3, report, and post-report oathgate check."""

from __future__ import annotations

import subprocess
import sys

from harness.dataset import REPO_ROOT
from harness.eval_v2_common import MODELS
OATHGATE = "/home/oops/ai-lab/oathgate/.venv/bin/oathgate"


def oath_check() -> None:
    run(OATHGATE, "check", "--spec", "oathgate_v2.toml", "--lock", "oathgate_v2.lock")


def run(*args: str) -> None:
    print("RUN", " ".join(args), flush=True)
    subprocess.run(args, cwd=REPO_ROOT, check=True)


def main() -> None:
    oath_check()
    for model in MODELS:
        run(sys.executable, "-m", "scripts.eval_v2_level2", "--model", model)
    for model in MODELS:
        for other in MODELS:
            subprocess.run(["ollama", "stop", other], cwd=REPO_ROOT, check=False)
        run(sys.executable, "-m", "harness.l3_eval_v2", "--model", model)
        subprocess.run(["ollama", "stop", model], cwd=REPO_ROOT, check=False)
    run(sys.executable, "-m", "scripts.eval_v2_report")
    oath_check()


if __name__ == "__main__":
    main()
