"""Unit tests for URL phishing heuristics."""

from __future__ import annotations

import unittest

from phishguard.url_analyzer import URLAnalyzer


class TestURLAnalyzer(unittest.TestCase):
    """Validate core URL phishing checks and scoring behavior."""

    def setUp(self) -> None:
        self.analyzer = URLAnalyzer()

    def test_ip_address_and_at_symbol_are_flagged(self) -> None:
        ip_result = self.analyzer.analyze("http://192.168.1.5/login")
        ip_checks = {entry["name"]: entry for entry in ip_result["checks"]}
        self.assertGreater(ip_checks["IP Address Check"]["score"], 0)

        at_result = self.analyzer.analyze("http://google.com@evil.com/login")
        at_checks = {entry["name"]: entry for entry in at_result["checks"]}
        self.assertGreater(at_checks["@ Symbol in URL"]["score"], 0)

    def test_homograph_domain_scores_high(self) -> None:
        result = self.analyzer.analyze("http://g00gle.com/security-check")
        checks = {entry["name"]: entry for entry in result["checks"]}

        self.assertEqual(checks["Homograph/Lookalike Detection"]["score"], 10)

    def test_safe_https_url_has_low_score(self) -> None:
        result = self.analyzer.analyze("https://www.example.com/help/contact")

        self.assertLess(result["normalized_score"], 20)

    def test_legitimate_brand_domain_not_flagged_as_homograph(self) -> None:
        result = self.analyzer.analyze("https://www.amazon.com/gp/css/order-history")
        checks = {entry["name"]: entry for entry in result["checks"]}

        self.assertEqual(checks["Homograph/Lookalike Detection"]["score"], 0)


if __name__ == "__main__":
    unittest.main()
