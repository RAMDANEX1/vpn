# config.py
# Réglages partagés par tout le monde
# Charge les variables depuis l'environnement pour éviter de hardcoder les secrets

import os

SERVEUR_IP    = os.getenv("VPN_IP", "127.0.0.1")
SERVEUR_PORT  = int(os.getenv("VPN_PORT", "9999"))
MOT_DE_PASSE  = os.getenv("VPN_PASSWORD", "changez_moi")  # jamais hardcodé
TAILLE_BUFFER = 4096
