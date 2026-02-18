"""Synthetic phishing dataset generator for PhishGuard model training."""

from __future__ import annotations

import csv
import random
from pathlib import Path
from typing import List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "phishing_dataset.csv"

COMPANIES = [
    "PayPal",
    "Amazon",
    "Apple",
    "Netflix",
    "Bank of America",
    "Wells Fargo",
    "Chase",
    "Microsoft",
]

NAMES = [
    "Sarah",
    "James",
    "Olivia",
    "Michael",
    "Daniel",
    "Priya",
    "Elliot",
    "Sophia",
    "Jordan",
    "Avery",
]

URGENCY_PHRASES = [
    "act now",
    "immediately",
    "within 24 hours",
    "urgent",
    "expires today",
    "account suspended",
    "verify your identity",
]

PHISHING_URLS = [
    "http://{slug}-security-check.xyz/login/verify",
    "http://secure-{slug}-account.top/update?session=44512",
    "http://{slug}-alert.click/confirm/account",
    "http://192.168.12.55/{slug}/signin",
    "http://{slug}.verify-now.info/auth/credential",
]

SAFE_URLS = [
    "https://www.amazon.com/orders",
    "https://www.paypal.com/myaccount/summary",
    "https://www.netflix.com/YourAccount",
    "https://support.apple.com/account",
    "https://www.chase.com/customer-service",
]

PHISHING_TEMPLATES = [
    "Dear Customer, we detected unauthorized activity on your {company} account. Please verify your identity {urgency} by clicking {url}",
    "Your {company} account has been limited. Update your information {urgency} or your account will be permanently suspended. Continue: {url}",
    "URGENT: Your bank account will be closed unless you confirm your credentials {urgency}. Click here now: {url}",
    "Congratulations! You've won a $1000 gift card. Claim your prize by entering your details at {url}",
    "Your package delivery failed. Click here to reschedule and pay the $1.99 redelivery fee: {url}",
]

LEGITIMATE_TEMPLATES = [
    "Hi {name}, here is your monthly statement for {month}. No action is needed, this is for your records.",
    "Your order #{order_id} has shipped. Track your package in your account dashboard: {url}",
    "Reminder: your appointment is scheduled for {day} at {time}. Let us know if you need to reschedule.",
    "Thank you for your purchase, {name}. Your receipt is attached and available in your account history.",
    "Hi team, please review the attached document before our meeting on {day}.",
    "Hello {name}, this is a confirmation that your subscription has been renewed successfully.",
]

MONTHS = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
]

DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
TIMES = ["9:00 AM", "11:30 AM", "2:00 PM", "4:15 PM"]


def _company_slug(company: str) -> str:
    """Convert a company name to URL-friendly slug."""
    return company.lower().replace(" ", "")


def _inject_typos(text: str, rng: random.Random, chance: float = 0.22) -> str:
    """Inject occasional phishing-like typo replacements for realism."""
    replacements = {
        "account": "acc0unt",
        "password": "pas5word",
        "verify": "ver1fy",
        "security": "secur1ty",
        "immediately": "immediatly",
        "click": "cl1ck",
    }

    words = text.split()
    transformed: List[str] = []

    for word in words:
        base = word.rstrip(".,!?:;")
        punct = word[len(base) :]
        normalized = base.lower()

        if normalized in replacements and rng.random() < chance:
            transformed.append(replacements[normalized] + punct)
        else:
            transformed.append(word)

    return " ".join(transformed)


def _build_phishing_sample(rng: random.Random) -> str:
    """Create a synthetic phishing-like message."""
    company = rng.choice(COMPANIES)
    template = rng.choice(PHISHING_TEMPLATES)
    urgency = rng.choice(URGENCY_PHRASES)
    url = rng.choice(PHISHING_URLS).format(slug=_company_slug(company))

    text = template.format(company=company, urgency=urgency, url=url)

    if rng.random() < 0.45:
        text += f" Please do not ignore this warning and respond {rng.choice(URGENCY_PHRASES)}."
    if rng.random() < 0.4:
        text = _inject_typos(text, rng)

    return text


def _build_legitimate_sample(rng: random.Random) -> str:
    """Create a synthetic legitimate business-like message."""
    name = rng.choice(NAMES)
    template = rng.choice(LEGITIMATE_TEMPLATES)

    text = template.format(
        name=name,
        month=rng.choice(MONTHS),
        day=rng.choice(DAYS),
        time=rng.choice(TIMES),
        order_id=rng.randint(10000, 99999),
        url=rng.choice(SAFE_URLS),
    )

    if rng.random() < 0.35:
        text += " If you have questions, reply to this email and our support team will help."

    return text


def generate_dataset(output_path: Path | str = DEFAULT_OUTPUT, total_samples: int = 2000, seed: int = 42) -> List[dict]:
    """Generate and save a labeled phishing dataset with balanced classes."""
    rng = random.Random(seed)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    phishing_count = total_samples // 2
    legitimate_count = total_samples - phishing_count

    rows: List[dict] = []
    for _ in range(phishing_count):
        rows.append({"text": _build_phishing_sample(rng), "label": 1})
    for _ in range(legitimate_count):
        rows.append({"text": _build_legitimate_sample(rng), "label": 0})

    rng.shuffle(rows)

    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["text", "label"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Synthetic dataset generated: {output}")
    print(f"[+] Total samples: {len(rows)} (phishing={phishing_count}, legitimate={legitimate_count})")
    return rows


if __name__ == "__main__":
    generate_dataset()
