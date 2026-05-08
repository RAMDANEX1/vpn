#!/bin/bash
# run_gui.sh — Lancer le client GUI VPN simplement sous Linux/Mac

cd "$(dirname "$0")"
export PYTHONPATH="$PWD"
python3 tools/run_gui.py
