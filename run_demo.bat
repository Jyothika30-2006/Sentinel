@echo off
title Sentinel - Live Desktop Demo
echo ========================================================
echo   Launching Sentinel Desktop Mascot + Investigation Demo
echo ========================================================
start "" python -m overlay.sentinel_pet --demo --draggable
python run.py samples\phishing.eml --no-llm --no-sandbox
pause
