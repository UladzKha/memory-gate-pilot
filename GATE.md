# Memory-write gate development integration

`memgate` is an independent Python package. Clone its repository alongside this
pilot, then install it into the Python environment used to run the harness:

```sh
git clone git@github.com:UladzKha/memgate.git ../memgate
python -m pip install -e ../memgate
```

The harness imports `memgate:Gate` from `harness/config/harness.yaml`. Run the
development-only report with `python -m scripts.gate_dev_eval`; it reads only
`results/dev/extract/` and `data/processed/email_dev/`, then writes
`results/checks/gate_dev_metrics.md` and `results/checks/gate_dev_errors.md`.
Use `python -m scripts.recompute_dev_summary` to refresh the saved development
extraction canary rates.
