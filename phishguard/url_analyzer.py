"""URL-focused heuristic phishing detection checks."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


class URLAnalyzer:
    """Run rule-based phishing checks for URLs."""

    SHORTENERS = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "cutt.ly",
        "rebrand.ly",
        "tiny.cc",
    }

    SUSPICIOUS_TLDS = {
        "xyz",
        "top",
        "buzz",
        "click",
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "pw",
        "cc",
        "info",
    }

    SUSPICIOUS_KEYWORDS = {
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "confirm",
        "signin",
        "banking",
        "password",
        "credential",
    }

    HOMOGRAPH_LOOKALIKES = {
        "paypa1.com",
        "g00gle.com",
        "amaz0n.com",
        "micros0ft.com",
        "faceb00k.com",
    }

    CHECK_MAX_SCORES = {
        "IP Address Check": 9,
        "Excessive Subdomain Check": 7,
        "URL Length Check": 5,
        "URL Shortener Detection": 6,
        "Suspicious TLD Check": 6,
        "Homograph/Lookalike Detection": 10,
        "@ Symbol in URL": 9,
        "HTTPS Check": 3,
        "Suspicious Keywords in URL Path": 7,
        "Double Extension Check": 8,
    }

    def analyze(self, url_string: str) -> dict:
        """Analyze a URL and return detailed phishing check results."""
        raw_url = (url_string or "").strip()
        normalized_url = self._normalize_url(raw_url)
        parsed = urlparse(normalized_url)
        hostname = (parsed.hostname or "").lower()

        checks = [
            self._ip_address_check(hostname),
            self._subdomain_check(hostname),
            self._length_check(raw_url),
            self._shortener_check(hostname),
            self._suspicious_tld_check(hostname),
            self._homograph_check(hostname),
            self._at_symbol_check(raw_url),
            self._https_check(parsed.scheme),
            self._suspicious_keyword_check(parsed.path, parsed.query, parsed.fragment),
            self._double_extension_check(parsed.path),
        ]

        total_score = sum(check["score"] for check in checks)
        max_possible_score = sum(self.CHECK_MAX_SCORES.values())
        normalized_score = (total_score / max_possible_score * 100.0) if max_possible_score else 0.0

        return {
            "url": raw_url,
            "checks": checks,
            "total_score": total_score,
            "max_possible_score": max_possible_score,
            "normalized_score": round(normalized_score, 2),
        }

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normalize URL so parser can reliably identify hostname and scheme."""
        if not url:
            return ""
        parsed = urlparse(url)
        if parsed.scheme:
            return url
        return f"http://{url}"

    def _ip_address_check(self, hostname: str) -> dict:
        """Flag raw IP addresses used instead of domain names."""
        is_ip = False
        host = hostname.strip("[]")
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            return self._build_check(
                name="IP Address Check",
                passed=False,
                score=9,
                detail="URL uses a raw IP address, which is a strong phishing indicator.",
            )
        return self._build_check(
            name="IP Address Check",
            passed=True,
            score=0,
            detail="URL uses a domain name instead of a raw IP address.",
        )

    def _subdomain_check(self, hostname: str) -> dict:
        """Flag unusually deep subdomain patterns."""
        dot_count = hostname.count(".")
        if dot_count >= 4:
            return self._build_check(
                name="Excessive Subdomain Check",
                passed=False,
                score=7,
                detail=f"Domain contains {dot_count} dots, which is abnormally deep.",
            )
        if dot_count == 3:
            return self._build_check(
                name="Excessive Subdomain Check",
                passed=False,
                score=3,
                detail="Domain contains 3 dots, which can be used to imitate trusted sites.",
            )
        return self._build_check(
            name="Excessive Subdomain Check",
            passed=True,
            score=0,
            detail="Domain depth looks normal.",
        )

    def _length_check(self, raw_url: str) -> dict:
        """Flag unusually long URLs often used for obfuscation."""
        length = len(raw_url)
        if length > 100:
            return self._build_check(
                name="URL Length Check",
                passed=False,
                score=5,
                detail=f"URL length is {length} characters (over 100).",
            )
        if length > 75:
            return self._build_check(
                name="URL Length Check",
                passed=False,
                score=3,
                detail=f"URL length is {length} characters (over 75).",
            )
        return self._build_check(
            name="URL Length Check",
            passed=True,
            score=0,
            detail="URL length is within a common range.",
        )

    def _shortener_check(self, hostname: str) -> dict:
        """Detect known URL shortener domains."""
        is_shortener = any(hostname == s or hostname.endswith(f".{s}") for s in self.SHORTENERS)
        if is_shortener:
            return self._build_check(
                name="URL Shortener Detection",
                passed=False,
                score=6,
                detail=f"Domain '{hostname}' is a known URL shortener.",
            )
        return self._build_check(
            name="URL Shortener Detection",
            passed=True,
            score=0,
            detail="No known URL shortener domain detected.",
        )

    def _suspicious_tld_check(self, hostname: str) -> dict:
        """Flag high-risk top-level domains commonly abused in phishing campaigns."""
        tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""
        if tld in self.SUSPICIOUS_TLDS:
            return self._build_check(
                name="Suspicious TLD Check",
                passed=False,
                score=6,
                detail=f"Top-level domain '.{tld}' is commonly used in phishing campaigns.",
            )
        return self._build_check(
            name="Suspicious TLD Check",
            passed=True,
            score=0,
            detail="Top-level domain is not on the suspicious list.",
        )

    def _homograph_check(self, hostname: str) -> dict:
        """Detect homograph attacks, lookalike domains, and IDN/punycode abuse."""
        if hostname in self.HOMOGRAPH_LOOKALIKES:
            return self._build_check(
                name="Homograph/Lookalike Detection",
                passed=False,
                score=10,
                detail=f"Known lookalike domain detected: {hostname}",
            )

        if hostname.startswith("xn--") or ".xn--" in hostname:
            return self._build_check(
                name="Homograph/Lookalike Detection",
                passed=False,
                score=10,
                detail="Punycode/IDN domain detected, which can hide homograph attacks.",
            )

        if any(ord(ch) > 127 for ch in hostname):
            return self._build_check(
                name="Homograph/Lookalike Detection",
                passed=False,
                score=10,
                detail="Non-ASCII characters detected in domain, possible IDN spoofing.",
            )

        lookalike_tokens = ("paypa1", "g00gle", "amaz0n", "micros0ft", "faceb00k")
        if any(token in hostname for token in lookalike_tokens):
            return self._build_check(
                name="Homograph/Lookalike Detection",
                passed=False,
                score=10,
                detail="Lookalike brand token found in domain.",
            )

        digit_brand_regexes = [
            r"paypa1",
            r"g00gle",
            r"amaz0n",
            r"micros0ft",
            r"faceb00k",
        ]
        if any(re.search(pattern, hostname) for pattern in digit_brand_regexes):
            return self._build_check(
                name="Homograph/Lookalike Detection",
                passed=False,
                score=10,
                detail="Brand-like domain with character substitutions detected.",
            )

        return self._build_check(
            name="Homograph/Lookalike Detection",
            passed=True,
            score=0,
            detail="No obvious homograph or lookalike patterns found.",
        )

    def _at_symbol_check(self, raw_url: str) -> dict:
        """Detect '@' redirects that can hide the real destination host."""
        if "@" in raw_url:
            return self._build_check(
                name="@ Symbol in URL",
                passed=False,
                score=9,
                detail="'@' symbol found in URL, which can obscure the true destination.",
            )
        return self._build_check(
            name="@ Symbol in URL",
            passed=True,
            score=0,
            detail="No '@' redirection pattern detected.",
        )

    def _https_check(self, scheme: str) -> dict:
        """Flag non-HTTPS URLs with a low weight."""
        if scheme.lower() != "https":
            return self._build_check(
                name="HTTPS Check",
                passed=False,
                score=3,
                detail="URL is not using HTTPS.",
            )
        return self._build_check(
            name="HTTPS Check",
            passed=True,
            score=0,
            detail="URL uses HTTPS.",
        )

    def _suspicious_keyword_check(self, path: str, query: str, fragment: str) -> dict:
        """Detect suspicious credential-harvesting keywords in URL path/query."""
        searchable = f"{path} {query} {fragment}".lower()
        keyword_count = sum(1 for keyword in self.SUSPICIOUS_KEYWORDS if keyword in searchable)

        if keyword_count >= 2:
            return self._build_check(
                name="Suspicious Keywords in URL Path",
                passed=False,
                score=7,
                detail=f"Detected {keyword_count} suspicious keywords in URL path/query.",
            )
        if keyword_count == 1:
            return self._build_check(
                name="Suspicious Keywords in URL Path",
                passed=False,
                score=4,
                detail="Detected one suspicious credential-related keyword in URL.",
            )
        return self._build_check(
            name="Suspicious Keywords in URL Path",
            passed=True,
            score=0,
            detail="No suspicious phishing keywords found in URL path/query.",
        )

    def _double_extension_check(self, path: str) -> dict:
        """Detect likely executable double-extension payload names."""
        pattern = re.compile(r"\.[a-z0-9]{1,5}\.(exe|bat|scr|js|vbs|ps1)(?:$|[?#/])", re.IGNORECASE)
        if pattern.search(path):
            return self._build_check(
                name="Double Extension Check",
                passed=False,
                score=8,
                detail="Detected a suspicious double extension ending in executable type.",
            )
        return self._build_check(
            name="Double Extension Check",
            passed=True,
            score=0,
            detail="No suspicious double extension pattern found.",
        )

    @staticmethod
    def _build_check(name: str, passed: bool, score: int, detail: str) -> dict:
        """Create a normalized check payload."""
        return {
            "name": name,
            "passed": passed,
            "score": score,
            "detail": detail,
        }
