"""Dev routing and provenance checks without loading models."""

from harness import extract
from harness.dataset import verify_dataset


def test_dev_uses_separate_paths_and_frozen_hashes():
    config = extract.load_config("dev")
    assert config["paths"]["output_dir"] == "results/dev"
    assert config["paths"]["dataset_dir"] == "data/processed/email_dev"
    assert len(extract.load_items(config, smoke=False)) == 600
    verify_dataset("dev")
    verify_dataset("eval")
