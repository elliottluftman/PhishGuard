"""Threat score combiner for heuristic and machine-learning outputs."""

from __future__ import annotations

from typing import Any, Dict


class ThreatScorer:
    """Calculate a final phishing threat score from multiple analysis engines."""

    def __init__(self, heuristic_weight: float = 0.4, ml_weight: float = 0.6) -> None:
        self.heuristic_weight = heuristic_weight
        self.ml_weight = ml_weight

    def calculate_score(self, heuristic_result: Dict[str, Any], ml_result: Dict[str, Any]) -> Dict[str, Any]:
        """Return final threat score and threat band using weighted scoring."""
        heuristic_score = float(heuristic_result.get("normalized_score", 0.0))
        ml_score = float(ml_result.get("confidence", 0.0)) * 100.0

        final_score = int(round((heuristic_score * self.heuristic_weight) + (ml_score * self.ml_weight)))
        final_score = max(0, min(100, final_score))

        if final_score <= 30:
            threat_level = "SAFE"
        elif final_score <= 60:
            threat_level = "SUSPICIOUS"
        else:
            threat_level = "LIKELY PHISHING"

        return {
            "final_score": final_score,
            "threat_level": threat_level,
            "heuristic_score": round(heuristic_score, 2),
            "ml_score": round(ml_score, 2),
            "heuristic_weight": self.heuristic_weight,
            "ml_weight": self.ml_weight,
        }
