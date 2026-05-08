@echo off
REM run_gui.bat — Lancer le client GUI VPN simplement sous Windows
cd /d "%~dp0"
set PYTHONPATH=%CD%
python tools/run_gui.py
pause
