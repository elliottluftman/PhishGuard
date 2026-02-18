# Data Notes

PhishGuard ships with a synthetic dataset generator in `generate_dataset.py`.

- Default output: `data/phishing_dataset.csv`
- Schema: `text,label`
  - `label=1` phishing
  - `label=0` legitimate
- Size: ~2,000 samples (balanced)

The data is synthetically generated from templates and phishing-inspired language patterns for educational experimentation. It is not intended as a production-grade security dataset.
