@echo off
title Sentinel - Build Executables
echo ========================================================
echo   Building Sentinel Executables using PyInstaller
echo ========================================================
echo.
echo Checking for PyInstaller...
pip install pyinstaller

echo.
echo Building Sentinel CLI (run.py)...
pyinstaller --name sentinel_cli --onefile --add-data "samples;samples" run.py

echo.
echo Building Sentinel Web Dashboard (app.py)...
pyinstaller --name sentinel_web --onedir --add-data "templates;templates" --add-data "samples;samples" app.py

echo.
echo Building Sentinel Guard (run_guard.py)...
pyinstaller --name sentinel_guard --onedir --add-data "templates;templates" --add-data "samples;samples" --add-data "overlay;overlay" run_guard.py

echo.
echo Build complete! Executables are located in the "dist" folder.
pause
