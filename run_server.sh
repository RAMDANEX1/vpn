#!/bin/bash
# run_server.sh — Lancer le serveur VPN simplement sous Linux/Mac

cd "$(dirname "$0")"
export PYTHONPATH="$PWD"
python3 tools/run_server.py
read -p "Press Enter to exit..."
