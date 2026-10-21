"""Evaluation harness for the frozen email dataset."""

from .dataset import verify_dataset
from .render import render_inbox

__all__ = ["render_inbox", "verify_dataset"]
