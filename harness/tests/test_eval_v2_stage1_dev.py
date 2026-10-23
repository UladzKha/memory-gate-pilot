"""DEV v2 input filter and safe call-reuse invariants."""

import unittest

from memgate import MemoryEntry

from scripts.eval_v2_stage1_dev import (clean_operating_point, email_text,
                                        filtered_item, guard_equivalent)


class Stage1Tests(unittest.TestCase):
    def test_clean_threshold_excludes_boundary_and_meets_cap(self):
        scores = [i / 100 for i in range(100)]
        threshold = clean_operating_point(scores)
        self.assertEqual(sum(score >= threshold for score in scores), 1)
        self.assertGreater(threshold, 0.98)
        self.assertLess(threshold, 0.99)

    def test_email_subject_and_body_only_and_original_order_preserved(self):
        email = {"subject": "Hello", "body": "World", "from": "sender@example.org"}
        self.assertEqual(email_text(email), "Subject: Hello\n\nWorld")
        item = {"emails": [{"subject": str(i), "body": str(i)} for i in range(3)]}
        scores = {"threshold": 0.5, "scores": {"x:0": 0.1, "x:1": 0.5, "x:2": 0.2}}
        filtered, kept = filtered_item("x", item, scores)
        self.assertEqual(kept, [0, 2])
        self.assertEqual([email["subject"] for email in filtered["emails"]], ["0", "2"])
        self.assertEqual(len(item["emails"]), 3)

    def test_reuse_requires_same_guard_relevant_memory(self):
        old = {"memory_entries": [{"text": "Keep REF_A", "outcome": "allow",
                                   "source_sender": "outside@example.org",
                                   "source_trusted": False, "targets": ["ref_a"]}]}
        new = [MemoryEntry("Keep REF_A", "allow_tainted", ["N2"],
                           "outside@example.org", False, ["ref_a"])]
        self.assertTrue(guard_equivalent("gate_full_strict", old, new))
        self.assertFalse(guard_equivalent("gate_full_tainted", old, new))
        self.assertFalse(guard_equivalent("gate_write", old,
                                         [MemoryEntry("Changed", "allow", [], None, False, [])]))


if __name__ == "__main__":
    unittest.main()
