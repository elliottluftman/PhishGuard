"""Unit tests for weighted threat scoring."""

from __future__ import annotations

import unittest

from phishguard.scorer import ThreatScorer


class TestThreatScorer(unittest.TestCase):
    """Validate score blending and threat-level mapping."""

    def setUp(self) -> None:
        self.scorer = ThreatScorer()

    def test_safe_classification(self) -> None:
        result = self.scorer.calculate_score(
            heuristic_result={"normalized_score": 10},
            ml_result={"confidence": 0.2},
        )
        self.assertEqual(result["threat_level"], "SAFE")

    def test_suspicious_classification(self) -> None:
        result = self.scorer.calculate_score(
            heuristic_result={"normalized_score": 45},
            ml_result={"confidence": 0.55},
        )
        self.assertEqual(result["threat_level"], "SUSPICIOUS")

    def test_phishing_classification(self) -> None:
        result = self.scorer.calculate_score(
            heuristic_result={"normalized_score": 70},
            ml_result={"confidence": 0.9},
        )
        self.assertEqual(result["threat_level"], "LIKELY PHISHING")


if __name__ == "__main__":
    unittest.main()
