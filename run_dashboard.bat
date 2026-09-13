@echo off
title Sentinel - Web Application Dashboard
echo ========================================================
echo   Starting Sentinel Web Application Server & Dashboard
echo ========================================================
echo.
echo Launching Flask Web Server at http://127.0.0.1:5000 ...
start http://127.0.0.1:5000
python app.py
pause
