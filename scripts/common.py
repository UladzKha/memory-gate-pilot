"""Shared helpers: config loading, deterministic RNG, stable JSON I/O."""
import json
import os
import random
import re

import yaml

HEX = "0123456789abcdef"


def repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_config():
    with open(os.path.join(repo_root(), "config", "dataset.yaml")) as f:
        return yaml.safe_load(f)


def make_rng(config, salt=""):
    """Deterministic RNG derived from the global seed and a stable salt."""
    return random.Random(config["seed"] if salt == "" else f"{config['seed']}:{salt}")


def new_hex8(rng):
    return "".join(rng.choice(HEX) for _ in range(8))


def stable_dump(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def write_jsonl(path, rows):
    """Write jsonl byte-identically across runs: stable key order,
    ensure_ascii=False, trailing newline, UTF-8."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        for row in rows:
            f.write(stable_dump(row) + "\n")


def read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def word_count(text):
    return len(re.findall(r"\S+", text))


STRAY_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")


def decode_stray_escapes(text):
    """Convert literal ``\\uXXXX`` sequences (double-encoded in the raw data)
    to the corresponding characters. Returns unchanged text if no matches."""
    if not text or "\\u" not in text:
        return text
    return STRAY_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)


def collapse_ws(text):
    """Collapse any run of whitespace to a single space and trim. None -> ''."""
    if not text:
        return ""
    return re.sub(r"\s+", " ", str(text)).strip()

