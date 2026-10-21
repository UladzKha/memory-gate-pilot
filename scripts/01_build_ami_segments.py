#!/usr/bin/env python3
"""Step 1: Build AMI meeting transcripts from the .segments.xml utterances,
then segment them and split meetings into disjoint carrier/clean groups.

Utterances:
  - One utterance = the words of one <segment> in `<MT>.<CH>.segments.xml`.
    The segment's nite:child href names a word-id range
    (`#id(MT.CH.wordsA)..id(MT.CH.wordsB)`) in the matching `<MT>.<CH>.words.xml`.
  - Same token rules as before: keep <w> only; drop <gap>/<disfmarker>/<vocalsound>;
    drop trunc="true"; attach punc="true" tokens to the previous word.
  - A meeting's utterances are ordered by the segments' transcriber_start time.
    Overlapping speech stays as separate utterances in start-time order (no
    word-by-word interleaving).

Segmentation:
  - Greedy pack to ~`ami.segment_words` words, cutting ONLY at utterance boundaries.
  - A trailing segment shorter than `ami.min_words` is merged into the previous one.
  - A meeting with under `ami.min_words` total words is dropped (and logged).

Writes:
  data/processed/ami_segments.jsonl
  data/processed/meeting_groups.json   (carrier/clean meeting split, disjoint)
  data/processed/ami_dropped.log       (meetings dropped for being too short)
Idempotent: deterministic parsing, fixed seed, stable JSON serialization.
"""
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (load_config, make_rng, repo_root, stable_dump, write_jsonl)

NS = "{http://nite.sourceforge.net/}"
WID = re.compile(r"\.words(\d+)$")


def parse_words_file(path, prefix):
    """Map integer word-id -> processed word dict for one channel's
    .words.xml. Keep <w> only; drop gap/disfmarker/vocalsound, trunc='true'.
    Punctuation tokens are folded into the previous word's text (no space).

    Returns a dict id -> text (only non-merged words remain in the map so
    callers can render a range as `id_map[lo] + " " + id_map[lo+1] + ...`).
    """
    root = ET.parse(path).getroot()
    id_map = {}
    n = 0
    for el in root:
        if el.tag.split("}")[-1] != "w":
            continue  # gap / disfmarker / vocalsound
        if el.get("trunc") == "true":
            n += 1
            continue
        text = (el.text or "").strip()
        if not text:
            n += 1
            continue
        if el.get("punc") == "true":
            if (n - 1) in id_map:
                id_map[n - 1] = id_map[n - 1] + text  # glue punctuation
            else:
                id_map[n] = text
            n += 1
            continue
        id_map[n] = text
        n += 1
    return id_map, n


def render_range(id_map, lo, hi):
    parts = [id_map[i] for i in range(lo, hi + 1) if i in id_map]
    return " ".join(parts)


def segs_for_channel(words_dir, segs_dir, mt, ch):
    """Return ordered list of (transcriber_start, [word indices...]) for a
    channel, by reading `<mt>.<ch>.segments.xml`."""
    spath = os.path.join(segs_dir, f"{mt}.{ch}.segments.xml")
    if not os.path.exists(spath):
        return []
    wpath = os.path.join(words_dir, f"{mt}.{ch}.words.xml")
    if not os.path.exists(wpath):
        return []
    id_map, _ = parse_words_file(wpath, f"{mt}.{ch}.words")
    root = ET.parse(spath).getroot()
    out = []
    for el in root:
        if el.tag.split("}")[-1] != "segment":
            continue
        child = el.find(NS + "child")
        href = child.get("href") if child is not None else ""
        ids = re.findall(r"id\(([^)]+)\)", href)
        nums = []
        for x in ids:
            m = WID.search(x)
            nums.append(int(m.group(1)) if m else None)
        nums = [x for x in nums if x is not None]
        if not nums:
            continue
        try:
            start = float(el.get("transcriber_start"))
        except (TypeError, ValueError):
            start = float("nan")
        out.append((start, nums, id_map))
    return out


def build_meeting_utts(words_dir, segs_dir, mt, channels):
    """Merge every channel of a meeting into utterances, ordered by the
    segment start time (stable -> by channel order on ties)."""
    rows = []  # (start, channel_idx, speaker, text)
    for ci, ch in enumerate(channels):
        for (start, nums, id_map) in segs_for_channel(words_dir, segs_dir, mt, ch):
            text = render_range(id_map, min(nums), max(nums)).strip()
            if not text:
                continue
            rows.append((start, ci, ch, text))
    rows.sort(key=lambda r: (r[0] if r[0] == r[0] else float("inf"), r[1]))
    return [{"speaker": r[2], "text": r[3]} for r in rows]


def word_count(text):
    return len(text.split())


def split_segments(utts, target):
    """Greedy pack to ~target words, cutting only at utterance boundaries, then
    fold a trailing segment shorter than min_tail into its predecessor."""
    raw = []
    cur = []
    wc = 0
    for u in utts:
        n = word_count(u["text"])
        if cur and wc + n > target:
            raw.append((cur, wc))
            cur = []
            wc = 0
        cur.append(u)
        wc += n
    if cur:
        raw.append((cur, wc))
    return raw


def main():
    cfg = load_config()
    root = repo_root()
    proc = os.path.join(root, cfg["paths"]["processed_root"])
    words_dir = os.path.join(root, cfg["paths"]["ami_words"])
    segs_dir = os.path.join(root, "data", "raw", "ami", "segments")
    target = int(cfg["ami"]["segment_words"])
    min_words = int(cfg["ami"].get("min_words", 1000))
    min_tail = min_words

    # Group words files into meetings by channel (MT.CH).
    files = sorted(glob.glob(os.path.join(words_dir, "*.words.xml")))
    by_meeting = defaultdict(dict)  # mt -> {channel: True}
    for p in files:
        base = os.path.basename(p)[:-len(".words.xml")]
        mt, ch = base.rsplit(".", 1)
        by_meeting[mt][ch] = True

    dropped = []
    segment_rows = []
    meeting_words = {}
    for mt in sorted(by_meeting):
        channels = sorted(by_meeting[mt].keys())
        utts = build_meeting_utts(words_dir, segs_dir, mt, channels)
        total_words = sum(word_count(u["text"]) for u in utts)
        if total_words < min_words:
            dropped.append({"meeting_id": mt, "total_words": total_words,
                            "reason": f"total words {total_words} < {min_words}"})
            continue
        meeting_words[mt] = total_words
        raw = split_segments(utts, target)
        # fold short trailing segment into its predecessor
        if len(raw) > 1 and raw[-1][1] < min_tail:
            last_utts, last_wc = raw[-1]
            prev_utts, prev_wc = raw[-2]
            raw[-1] = None
            raw[-2] = (prev_utts + last_utts, prev_wc + last_wc)
            raw = raw[:-1]
        for i, (utts_i, wc_i) in enumerate(raw):
            segment_rows.append({
                "segment_id": f"{mt}-{i:03d}",
                "meeting_id": mt,
                "words": wc_i,
                "utterances": utts_i,
            })

    # Disjoint seeded carrier/clean meeting split over the KEPT meetings.
    kept_meetings = sorted(meeting_words.keys())
    rng = make_rng(cfg, "meeting_split")
    pool = list(kept_meetings)
    rng.shuffle(pool)
    n_carrier = max(1, int(round(len(pool) * float(cfg["ami"]["carrier_ratio"]))))
    carrier_meetings = set(pool[:n_carrier])
    clean_meetings = set(pool[n_carrier:])

    out = os.path.join(proc, "ami_segments.jsonl")
    write_jsonl(out, segment_rows)
    with open(os.path.join(proc, "meeting_groups.json"), "w", encoding="utf-8", newline="") as f:
        f.write(stable_dump({
            "carrier": sorted(carrier_meetings),
            "clean": sorted(clean_meetings),
        }) + "\n")
    with open(os.path.join(proc, "ami_dropped.log"), "w", encoding="utf-8", newline="") as f:
        for d in dropped:
            f.write(stable_dump(d) + "\n")

    n_carrier_segs = sum(1 for s in segment_rows if s["meeting_id"] in carrier_meetings)
    words = [s["words"] for s in segment_rows]
    import statistics
    print(f"meetings kept={len(kept_meetings)} (dropped={len(dropped)}) | "
          f"segments={len(segment_rows)} "
          f"(carrier={len(carrier_meetings)} clean={len(clean_meetings)} meetings, "
          f"{n_carrier_segs} carrier segments)")
    if words:
        print(f"segment words: min={min(words)} median={int(statistics.median(words))} max={max(words)}")
    for d in dropped:
        print("  dropped meeting:", d)


if __name__ == "__main__":
    main()
