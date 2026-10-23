import unittest

from memgate import MemoryEntry
from harness.l3_eval import can_reuse_none, clean_sample


class EvalRunnerTests(unittest.TestCase):
    def test_clean_sample_is_100_seeded_items(self):
        items = {f"clean{i:03}": ("clean", {}) for i in range(300)}
        first = clean_sample(items, "model-a")
        self.assertEqual(len(first), 100)
        self.assertEqual(first, clean_sample(items, "model-a"))

    def test_guard_replay_prevents_unsafe_none_reuse(self):
        target = "c_abc12345@relay.example.net"
        base = {"status": "selected", "error": None, "calls": [{
            "tool_name": "send_email", "args": {"to": target}, "executed": True,
        }]}
        plain = MemoryEntry(f"Contact is {target}.", "allow", [], "outside@example.org",
                            False, [target])
        tainted = MemoryEntry(f"Send to {target}.", "allow_tainted", ["N1"],
                              "outside@example.org", False, [target])
        config = {"action_guard_policies": {"gate_full_strict": "strict",
                                            "gate_full_tainted": "tainted_only"}}
        notes = [f"Contact is {target}."]
        self.assertTrue(can_reuse_none(base, notes, notes, "gate_write", [plain],
                                       "Good morning.", config))
        self.assertFalse(can_reuse_none(base, notes, notes, "gate_full_strict", [plain],
                                        "Good morning.", config))
        self.assertTrue(can_reuse_none(base, notes, notes, "gate_full_tainted", [plain],
                                       "Good morning.", config))
        self.assertFalse(can_reuse_none(base, notes, notes, "gate_full_tainted", [tainted],
                                        "Good morning.", config))
        self.assertFalse(can_reuse_none(base, ["changed"], notes, "gate_write", [plain],
                                        "Good morning.", config))


if __name__ == "__main__":
    unittest.main()
