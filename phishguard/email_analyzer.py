"""Email-focused heuristic phishing detection checks."""

from __future__ import annotations

import html as html_lib
import re
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from urllib.parse import urlparse


class EmailAnalyzer:
    """Run rule-based checks against raw email headers and body content."""

    URGENCY_PHRASES = (
        "act now",
        "immediately",
        "urgent",
        "expires today",
        "account suspended",
        "verify your identity",
        "unauthorized activity",
        "click here now",
        "within 24 hours",
        "limited time",
    )

    GENERIC_GREETINGS = (
        "dear customer",
        "dear user",
        "dear account holder",
        "valued customer",
    )

    FREE_PROVIDERS = {
        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "outlook.com",
        "aol.com",
        "protonmail.com",
        "icloud.com",
    }

    OFFICIAL_BRAND_TERMS = (
        "paypal",
        "amazon",
        "apple",
        "netflix",
        "bank",
        "wells fargo",
        "bank of america",
        "chase",
    )

    CHECK_MAX_SCORES = {
        "Sender/Reply-To Mismatch": 8,
        "Suspicious Sender Domain": 5,
        "Missing or Suspicious Headers": 3,
        "Display Name Spoofing": 9,
        "Urgency Language Detection": 9,
        "Link Count": 4,
        "Link Text Mismatch": 10,
        "Attachment References": 7,
        "Generic Greeting": 3,
        "Spelling/Grammar Indicators": 5,
    }

    def analyze(self, raw_email_text: str) -> dict:
        """Analyze an email payload and return detailed heuristic checks."""
        message = Parser(policy=policy.default).parsestr(raw_email_text or "")
        body_text = self._extract_body_from_message(message)

        checks = [
            self._sender_reply_to_mismatch_check(message),
            self._suspicious_sender_domain_check(message, body_text),
            self._header_security_check(message),
            self._display_name_spoofing_check(message),
            self._urgency_language_check(body_text),
            self._link_count_check(body_text),
            self._link_text_mismatch_check(raw_email_text, body_text),
            self._attachment_reference_check(body_text),
            self._generic_greeting_check(body_text),
            self._spelling_indicator_check(body_text),
        ]

        total_score = sum(check["score"] for check in checks)
        max_possible_score = sum(self.CHECK_MAX_SCORES.values())
        normalized_score = (total_score / max_possible_score * 100.0) if max_possible_score else 0.0

        return {
            "email": raw_email_text,
            "body": body_text,
            "checks": checks,
            "total_score": total_score,
            "max_possible_score": max_possible_score,
            "normalized_score": round(normalized_score, 2),
        }

    def extract_body(self, raw_email_text: str) -> str:
        """Extract text body from a raw email string."""
        message = Parser(policy=policy.default).parsestr(raw_email_text or "")
        return self._extract_body_from_message(message)

    def _sender_reply_to_mismatch_check(self, message) -> dict:
        """Compare From and Reply-To domains for suspicious mismatch."""
        from_domain = self._extract_domain(message.get("From", ""))
        reply_to_domain = self._extract_domain(message.get("Reply-To", ""))

        if from_domain and reply_to_domain and from_domain != reply_to_domain:
            return self._build_check(
                "Sender/Reply-To Mismatch",
                False,
                8,
                f"From domain '{from_domain}' differs from Reply-To domain '{reply_to_domain}'.",
            )

        if reply_to_domain:
            detail = "Reply-To domain matches sender domain."
        else:
            detail = "No Reply-To header mismatch detected."
        return self._build_check("Sender/Reply-To Mismatch", True, 0, detail)

    def _suspicious_sender_domain_check(self, message, body_text: str) -> dict:
        """Detect free email providers posing as official organizations."""
        from_domain = self._extract_domain(message.get("From", ""))
        body_lower = body_text.lower()

        is_free_provider = any(
            from_domain == domain or from_domain.endswith(f".{domain}") for domain in self.FREE_PROVIDERS
        )
        mentions_brands = any(term in body_lower for term in self.OFFICIAL_BRAND_TERMS)

        if is_free_provider and mentions_brands:
            return self._build_check(
                "Suspicious Sender Domain",
                False,
                5,
                f"Sender domain '{from_domain}' is a free provider used in official-looking content.",
            )

        return self._build_check(
            "Suspicious Sender Domain",
            True,
            0,
            "Sender domain pattern does not match this free-provider impersonation signal.",
        )

    def _header_security_check(self, message) -> dict:
        """Check whether SPF/DKIM/DMARC indicators appear in headers."""
        header_names = {header.lower() for header in message.keys()}
        auth_results = " ".join(message.get_all("Authentication-Results", [])).lower()

        spf_present = "received-spf" in header_names or "spf=" in auth_results
        dkim_present = "dkim-signature" in header_names or "dkim=" in auth_results
        dmarc_present = "dmarc-filter" in header_names or "dmarc=" in auth_results

        present_count = int(spf_present) + int(dkim_present) + int(dmarc_present)
        if present_count < 2:
            missing = [
                name
                for name, present in (
                    ("SPF", spf_present),
                    ("DKIM", dkim_present),
                    ("DMARC", dmarc_present),
                )
                if not present
            ]
            return self._build_check(
                "Missing or Suspicious Headers",
                False,
                3,
                f"Missing expected auth signals: {', '.join(missing)}.",
            )

        return self._build_check(
            "Missing or Suspicious Headers",
            True,
            0,
            "Email contains multiple SPF/DKIM/DMARC-related indicators.",
        )

    def _display_name_spoofing_check(self, message) -> dict:
        """Detect display names that impersonate another domain."""
        from_header = message.get("From", "")
        display_name, email_addr = parseaddr(from_header)
        sender_domain = self._extract_domain(email_addr)

        display_name_lower = display_name.lower()
        domain_hints = set()

        for email_match in re.findall(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", display_name_lower):
            domain_hints.add(email_match.split("@", 1)[1])

        for domain_match in re.findall(r"\b[a-z0-9-]+\.[a-z]{2,}\b", display_name_lower):
            domain_hints.add(domain_match)

        for hinted_domain in domain_hints:
            if sender_domain and hinted_domain != sender_domain and not sender_domain.endswith(hinted_domain):
                return self._build_check(
                    "Display Name Spoofing",
                    False,
                    9,
                    f"Display name references '{hinted_domain}' but actual sender domain is '{sender_domain}'.",
                )

        return self._build_check(
            "Display Name Spoofing",
            True,
            0,
            "No obvious display-name domain spoofing pattern detected.",
        )

    def _urgency_language_check(self, body_text: str) -> dict:
        """Score urgency pressure language frequently found in phishing content."""
        body_lower = body_text.lower()
        phrase_count = sum(1 for phrase in self.URGENCY_PHRASES if phrase in body_lower)

        if phrase_count >= 5:
            return self._build_check(
                "Urgency Language Detection",
                False,
                9,
                f"Detected {phrase_count} urgency phrases in the email body.",
            )
        if phrase_count >= 3:
            return self._build_check(
                "Urgency Language Detection",
                False,
                6,
                f"Detected {phrase_count} urgency phrases in the email body.",
            )
        if phrase_count >= 1:
            return self._build_check(
                "Urgency Language Detection",
                False,
                3,
                f"Detected {phrase_count} urgency phrase(s) in the email body.",
            )

        return self._build_check(
            "Urgency Language Detection",
            True,
            0,
            "No urgency-pressure language found.",
        )

    def _link_count_check(self, body_text: str) -> dict:
        """Flag unusually high link density in email content."""
        links = re.findall(r"(?:https?://|www\.)[^\s<>'\"]+", body_text, flags=re.IGNORECASE)
        count = len(links)

        if count > 5:
            return self._build_check(
                "Link Count",
                False,
                4,
                f"Email contains {count} links, which is unusually high.",
            )
        if 3 <= count <= 5:
            return self._build_check(
                "Link Count",
                False,
                2,
                f"Email contains {count} links.",
            )

        return self._build_check("Link Count", True, 0, "Link count appears normal.")

    def _link_text_mismatch_check(self, raw_email_text: str, body_text: str) -> dict:
        """Detect mismatches where displayed domain differs from destination href domain."""
        anchor_pattern = re.compile(
            r"<a\s+[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
            flags=re.IGNORECASE | re.DOTALL,
        )

        for href, visible_html in anchor_pattern.findall(raw_email_text):
            href_domain = self._extract_url_domain(href)
            visible_text = self._strip_html(visible_html)
            visible_domain = self._extract_domain_like_text(visible_text)

            if href_domain and visible_domain:
                same_domain = href_domain == visible_domain
                subdomain_match = href_domain.endswith(f".{visible_domain}") or visible_domain.endswith(f".{href_domain}")
                if not same_domain and not subdomain_match:
                    return self._build_check(
                        "Link Text Mismatch",
                        False,
                        10,
                        f"Displayed domain '{visible_domain}' differs from target '{href_domain}'.",
                    )

        return self._build_check(
            "Link Text Mismatch",
            True,
            0,
            "No display-text vs destination-domain mismatch detected.",
        )

    def _attachment_reference_check(self, body_text: str) -> dict:
        """Flag references to executable attachment filenames."""
        if re.search(r"\b[\w.-]+\.(exe|bat|scr|js|vbs|ps1)\b", body_text, flags=re.IGNORECASE):
            return self._build_check(
                "Attachment References",
                False,
                7,
                "Body references an executable attachment type.",
            )
        return self._build_check(
            "Attachment References",
            True,
            0,
            "No executable attachment references found.",
        )

    def _generic_greeting_check(self, body_text: str) -> dict:
        """Detect generic, non-personalized greetings common in bulk phishing."""
        lines = [line.strip().lower() for line in body_text.splitlines() if line.strip()]
        opening_lines = lines[:6]

        for line in opening_lines:
            if any(line.startswith(greeting) for greeting in self.GENERIC_GREETINGS):
                return self._build_check(
                    "Generic Greeting",
                    False,
                    3,
                    f"Opening uses generic greeting: '{line}'.",
                )

        return self._build_check(
            "Generic Greeting",
            True,
            0,
            "Greeting appears personalized or neutral.",
        )

    def _spelling_indicator_check(self, body_text: str) -> dict:
        """Detect obvious phishing-style misspellings and character replacements."""
        suspicious_patterns = [
            r"\bacc0unt\b",
            r"\bpas5word\b",
            r"\bver1fy\b",
            r"\bsecur1ty\b",
            r"\bimmediatly\b",
            r"\bupdtae\b",
            r"\bcl1ck\b",
        ]

        indicator_hits = sum(
            1 for pattern in suspicious_patterns if re.search(pattern, body_text, flags=re.IGNORECASE)
        )

        if indicator_hits > 0:
            return self._build_check(
                "Spelling/Grammar Indicators",
                False,
                5,
                f"Detected {indicator_hits} suspicious spelling/replacement indicator(s).",
            )

        return self._build_check(
            "Spelling/Grammar Indicators",
            True,
            0,
            "No obvious phishing-style spelling indicators detected.",
        )

    @staticmethod
    def _extract_domain(address: str) -> str:
        """Extract lowercase domain from an email address-like string."""
        _, email_addr = parseaddr(address)
        if "@" not in email_addr:
            return ""
        return email_addr.rsplit("@", 1)[-1].lower()

    @staticmethod
    def _extract_url_domain(url_text: str) -> str:
        """Extract hostname from URL text."""
        candidate = (url_text or "").strip()
        if not candidate:
            return ""
        if not re.match(r"^[a-z]+://", candidate, flags=re.IGNORECASE):
            candidate = f"http://{candidate}"
        return (urlparse(candidate).hostname or "").lower()

    @staticmethod
    def _extract_domain_like_text(text: str) -> str:
        """Extract the first domain-looking token from plain text."""
        if not text:
            return ""
        match = re.search(r"(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})", text.lower())
        if not match:
            return ""
        return match.group(1)

    @staticmethod
    def _strip_html(content: str) -> str:
        """Convert HTML fragment to plain text."""
        text = re.sub(r"<[^>]+>", " ", content or "")
        text = html_lib.unescape(text)
        return re.sub(r"\s+", " ", text).strip()

    def _extract_body_from_message(self, message) -> str:
        """Safely extract readable body content from an email message object."""
        extracted_parts = []

        if message.is_multipart():
            for part in message.walk():
                content_type = (part.get_content_type() or "").lower()
                disposition = (part.get_content_disposition() or "").lower()
                if disposition == "attachment":
                    continue

                try:
                    payload = part.get_content()
                except Exception:
                    payload = ""

                if not payload:
                    continue

                if content_type == "text/plain":
                    extracted_parts.append(str(payload))
                elif content_type == "text/html" and not extracted_parts:
                    extracted_parts.append(self._strip_html(str(payload)))
        else:
            try:
                payload = message.get_content()
            except Exception:
                payload = ""

            content_type = (message.get_content_type() or "").lower()
            if content_type == "text/html":
                extracted_parts.append(self._strip_html(str(payload)))
            else:
                extracted_parts.append(str(payload))

        body_text = "\n".join(part for part in extracted_parts if part).strip()
        return body_text

    @staticmethod
    def _build_check(name: str, passed: bool, score: int, detail: str) -> dict:
        """Create a normalized check payload."""
        return {
            "name": name,
            "passed": passed,
            "score": score,
            "detail": detail,
        }
