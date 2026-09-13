@echo off
title Sentinel CLI - Threat Investigation Demo
echo ========================================================
echo   Running Sentinel CLI Forensic Investigation Demo
echo ========================================================
echo.
python run.py samples\phishing.eml --no-llm --no-sandbox
pause
