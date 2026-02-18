#!/usr/bin/env bash
set -euo pipefail

HOST="${1:-http://127.0.0.1:5001}"

curl --fail --silent "$HOST/healthz" && echo
curl --fail --silent "$HOST/readyz" && echo
