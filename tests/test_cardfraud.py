import os
import unittest

from banksoc import cardfraud as cf

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "real_data", "creditcard_sample.csv")


class AucTests(unittest.TestCase):
    def test_perfect_and_inverted(self):
        self.assertEqual(cf.roc_auc([1, 2, 3, 4], [0, 0, 1, 1]), 1.0)
        self.assertEqual(cf.roc_auc([4, 3, 2, 1], [0, 0, 1, 1]), 0.0)

    def test_ties_get_half(self):
        self.assertAlmostEqual(cf.roc_auc([1, 1, 1, 1], [0, 1, 0, 1]), 0.5)

    def test_average_precision(self):
        self.assertEqual(cf.average_precision([0.9, 0.8, 0.1], [1, 1, 0]), 1.0)
        self.assertAlmostEqual(cf.average_precision([0.9, 0.8, 0.7], [0, 1, 1]), (1 / 2 + 2 / 3) / 2)

    def test_alert_budget(self):
        b = cf.alert_budget([0.9, 0.8, 0.1, 0.2], [1, 0, 1, 0], 2)
        self.assertEqual((b["frauds_caught"], b["recall"], b["precision"]), (1, 0.5, 0.5))

    def test_fit_needs_both_classes(self):
        with self.assertRaises(ValueError):
            cf.LogisticModel().fit([{"Class": 0}] * 5)


class RealDataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = cf.load(SAMPLE)

    def test_sample_is_the_real_dataset_shape(self):
        self.assertGreater(len(self.rows), 6000)
        self.assertEqual(sum(1 for r in self.rows if r["Class"] == 1), 492)
        self.assertIn("V28", self.rows[0])
        self.assertEqual([r["Time"] for r in self.rows], sorted(r["Time"] for r in self.rows))

    def test_model_ranks_future_fraud_well(self):
        res, model, test, scores = cf.evaluate(self.rows)
        self.assertGreater(res["roc_auc"], 0.95)
        self.assertGreater(res["average_precision"], 0.5)
        self.assertTrue(cf.top_alerts(model, test, scores, 3)[0]["why"])


if __name__ == "__main__":
    unittest.main()
