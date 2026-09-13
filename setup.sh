#!/usr/bin/env bash
# =====================================================================
# Sentinel — one-shot local setup (Linux/macOS). No cloud dependencies.
#
# Usage:  bash setup.sh
#
# Installs: Python deps (venv), and OPTIONALLY builds the Docker sandbox
# image and pulls the Ollama model. Everything is skippable.
# =====================================================================
set -euo pipefail

cd "$(dirname "$0")"

echo "==> [1/4] Creating Python virtual environment"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

echo "==> [2/4] Installing Python dependencies"
pip install --upgrade pip
pip install -r requirements.txt

echo "==> [3/4] Docker sandbox image (optional)"
if command -v docker >/dev/null 2>&1; then
    read -r -p "Build the sandbox image (sentinel-sandbox)? [y/N] " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        docker build -t sentinel-sandbox:latest sandbox/
    fi
else
    echo "    Docker not found — static_file_scan will fall back to host tools."
fi

echo "==> [4/4] Ollama model (optional)"
if command -v ollama >/dev/null 2>&1; then
    read -r -p "Pull the local LLM model (llama3.1:8b)? [y/N] " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        ollama pull llama3.1:8b
    fi
else
    echo "    Ollama not found — agent will run in deterministic (no-LLM) mode."
fi

cat <<'EOF'

Done! Next steps:
  1. Optional: copy .env.example -> .env and add API keys (VirusTotal/AbuseIPDB).
  2. Run an investigation:
        source .venv/bin/activate
        python run.py samples/phishing.eml
  3. (Optional) launch the desktop mascot over Gmail:
        python overlay/run_overlay.py --follow --risk-file /tmp/sentinel_risk.json
EOF
