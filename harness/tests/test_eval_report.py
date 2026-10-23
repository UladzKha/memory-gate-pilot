import unittest

from scripts.gate_eval_report import holm, mcnemar_one_sided, strata, wilson


class EvalReportTests(unittest.TestCase):
    def test_exact_paired_test_is_directional(self):
        baseline = {"a": True, "b": True, "c": True, "d": False}
        candidate = {"a": False, "b": False, "c": False, "d": False}
        self.assertEqual(mcnemar_one_sided(candidate, baseline), (3, 0, 0.125))
        self.assertEqual(mcnemar_one_sided(baseline, candidate), (0, 3, 1.0))

    def test_holm_correction_is_monotone_across_three_models(self):
        adjusted = holm({"a": 0.01, "b": 0.03, "c": 0.02})
        self.assertEqual(adjusted, {"a": 0.03, "c": 0.04, "b": 0.04})

    def test_wilson_and_attack_strata(self):
        low, high = wilson(10, 100)
        self.assertLess(low, 0.10)
        self.assertGreater(high, 0.10)
        self.assertLess(high, 0.20)
        self.assertEqual(strata({"source": "llmail", "variant": "memory"}),
                         ("all", "llmail", "memory", "llmail_memory"))


if __name__ == "__main__":
    unittest.main()
