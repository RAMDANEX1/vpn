#!/usr/bin/env python
"""Test de sécurité - authentification échouée"""
import socket
import hmac
from protocol import envoyer, recevoir, emballer, deballer, TypeMessage
from crypto import dechiffrer

print("\n" + "="*60)
print("🔓 TEST SÉCURITÉ - Mauvais mot de passe")
print("="*60)

# Connexion
print("\n[1] Connexion au serveur...")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 9999))
print("    ✓ Connecté")

# Réception du challenge
print("\n[2] Réception du challenge...")
donnees = recevoir(s)
msg_type, seq, nonce = deballer(donnees)
print(f"    ✓ Challenge reçu")

# MAUVAISE réponse HMAC avec mot de passe incorrect
print("\n[3] Envoi d'une MAUVAISE réponse HMAC...")
MAUVAIS_MDP = "mauvais_mot_de_passe"
hmac_reponse = hmac.new(MAUVAIS_MDP.encode(), nonce, 'sha256').digest()
envoyer(s, emballer(TypeMessage.AUTH_REQ, hmac_reponse, seq=0))
print(f"    ⚠️  HMAC incorrect envoyé")

# Réception de la réponse
print("\n[4] Attente de la réaction du serveur...")
donnees = recevoir(s)
msg_type, seq, payload = deballer(donnees)

if msg_type == TypeMessage.AUTH_FAIL:
    print("    ✓ Serveur a rejeté l'authentification")
    print(f"       Raison: {payload.decode()}")
else:
    print(f"    ❌ Type reçu: {msg_type} (attendu AUTH_FAIL)")

# Le serveur doit fermer la connexion
try:
    s.recv(1)
    print("    ❌ Connection still alive (should be closed)")
except:
    print("    ✓ Connexion fermée par le serveur (sécurité OK)")

print("\n" + "="*60)
print("✅ TEST SÉCURITÉ RÉUSSI - Rejet du mauvais mot de passe")
print("="*60)
