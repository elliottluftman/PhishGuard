# 🛡️ PhishGuard — AI-Powered Phishing Email & URL Detector

> A dual-engine phishing detection platform combining rule-based security heuristics with machine learning to identify malicious emails and URLs.

![PhishGuard Screenshot](screenshots/analysis.png)

## How It Works

PhishGuard uses a **two-engine scoring system**:

### Engine 1: Heuristic Analysis (40%)
PhishGuard applies explicit anti-phishing checks such as:
- URL structure analysis (IP usage, subdomain depth, suspicious TLDs)
- Homograph/lookalike detection (e.g., `g00gle.com`, punycode)
- Email header anomalies (reply-to mismatch, display-name spoofing)
- Urgency pressure language and attachment indicators
- Link mismatch and suspicious keyword patterns

### Engine 2: ML Classifier (60%)
A text classifier trained on phishing vs legitimate samples:
- TF-IDF features with unigrams/bigrams
- Trains and compares Logistic Regression, Random Forest, and Naive Bayes
- Auto-selects the best model by F1 score
- Model artifacts saved locally in `models/`

### Final Threat Score
- **0-30**: ✅ SAFE
- **31-60**: ⚠️ SUSPICIOUS
- **61-100**: 🚨 LIKELY PHISHING

## Project Highlights

- Production-ready Flask app factory with secure defaults
- `/healthz` and `/readyz` for uptime and readiness checks
- Request ID tagging + structured request logging
- Sliding-window API rate limiting
- Security headers (CSP, X-Frame-Options, no-sniff, permissions policy)
- Interactive SOC-style dashboard with animated threat dial
- One-click sample payloads for live demos
- No API keys required

## Quick Start

### 1. Install
```bash
git clone https://github.com/elliottluftman/PhishGuard.git
cd PhishGuard
python -m pip install -r requirements.txt
```

### 2. Run
```bash
python run.py
```

Open `http://localhost:5001`.

### 3. Retrain (Optional)
```bash
python phishguard/train_model.py
```

## Always-On Deployment

### Option A: Docker (recommended)
```bash
cp .env.example .env
docker compose up -d --build
```

- Service restarts automatically (`restart: unless-stopped`)
- Health endpoint: `http://localhost:5001/healthz`

### Option B: Gunicorn (host install)
```bash
cp .env.example .env
gunicorn -c gunicorn.conf.py wsgi:app
```

Shortcut script:
```bash
./scripts/start_prod.sh
```

### Option C: macOS launchd (auto-start on login/reboot)
Use template: `deploy/com.elliottluftman.phishguard.plist`

```bash
cp deploy/com.elliottluftman.phishguard.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.elliottluftman.phishguard.plist
launchctl start com.elliottluftman.phishguard
```

## Environment Variables

Configured via `.env` (see `.env.example`):

- `PHISHGUARD_HOST`, `PHISHGUARD_PORT`, `PHISHGUARD_DEBUG`
- `PHISHGUARD_SECRET_KEY`, `PHISHGUARD_LOG_LEVEL`
- `PHISHGUARD_RATE_LIMIT_REQUESTS`, `PHISHGUARD_RATE_LIMIT_WINDOW_SECONDS`
- `PHISHGUARD_ENABLE_CORS`, `PHISHGUARD_CORS_ORIGINS`
- `PHISHGUARD_USE_WAITRESS` and waitress tuning values
- Gunicorn worker/thread/timeout values

## API Reference

### `POST /api/analyze`
Request:
```json
{
  "type": "url",
  "content": "http://secure-paypa1-account.xyz/login"
}
```

### `GET /api/samples`
Returns demo phishing/safe URLs and sample emails used by the UI.

### `GET /healthz`
Liveness check endpoint.

### `GET /readyz`
Readiness check for model artifacts.

Quick check script:
```bash
./scripts/check_health.sh
```

## Tests

```bash
python -m unittest tests/test_url_analyzer.py
```

## Tech Stack

- **Backend**: Python, Flask
- **ML/NLP**: Scikit-learn, TF-IDF
- **Web Serving**: Waitress / Gunicorn
- **Frontend**: HTML, CSS, JavaScript
- **Containers**: Docker + Compose

## ⚠️ Disclaimer

PhishGuard is for educational and defensive analysis workflows. It is **not** a substitute for enterprise mail security infrastructure or SOC verification processes.

## Author

**Elliott Luftman** — [LinkedIn](https://www.linkedin.com/in/elliottluftman) | [Portfolio](https://elliottluftman.github.io)
