#!/usr/bin/env python3
# test_password_sync.py — Diagnostic du mot de passe

import os
import sys
from config import MOT_DE_PASSE

print("=" * 60)
print("🔐 DIAGNOSTIC MOT DE PASSE")
print("=" * 60)

# Vérifier la variable d'environnement
env_password = os.getenv("VPN_PASSWORD")
print(f"\n1️⃣ Variable d'environnement VPN_PASSWORD:")
if env_password:
    print(f"   ✅ DÉFINIE : {env_password}")
else:
    print(f"   ❌ NON DÉFINIE (None)")

# Vérifier le mot de passe dans config.py
print(f"\n2️⃣ Mot de passe dans config.py (MOT_DE_PASSE):")
print(f"   📝 Valeur : {MOT_DE_PASSE}")

# Vérifier la correspondance
print(f"\n3️⃣ SYNCHRONISATION:")
if env_password and env_password == MOT_DE_PASSE:
    print(f"   ✅ OK : Environnement = Config")
    print(f"   Mot de passe actif : '{MOT_DE_PASSE}'")
elif env_password and env_password != MOT_DE_PASSE:
    print(f"   ❌ DÉSYNCHRONISÉ!")
    print(f"   Environnement  : '{env_password}'")
    print(f"   Config (défaut): '{MOT_DE_PASSE}'")
    print(f"   >>> Le serveur utilisera : '{MOT_DE_PASSE}'")
else:
    print(f"   ⚠️  Pas de variable d'environnement, utilise le défaut")
    print(f"   >>> Le serveur utilisera : '{MOT_DE_PASSE}'")

print(f"\n" + "=" * 60)
print("✅ À retenir pour ta connexion GUI:")
print(f"   Rentre ce mot de passe exactement : '{MOT_DE_PASSE}'")
print("=" * 60)
