@echo off
REM run_server.bat — Lancer le serveur VPN simplement sous Windows
cd /d "%~dp0"
set PYTHONPATH=%CD%
python tools/run_server.py
pause
