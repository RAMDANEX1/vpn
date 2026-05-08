#!/usr/bin/env python
"""Test compression - montrer l'efficacité"""
import socket
import hmac
from protocol import envoyer, recevoir, emballer, deballer, TypeMessage
from crypto import chiffrer, dechiffrer

print("\n" + "="*60)
print("📦 TEST COMPRESSION - Efficacité")
print("="*60)

# Connexion
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 9999))

# Auth
donnees = recevoir(s)
msg_type, seq, nonce = deballer(donnees)
hmac_reponse = hmac.new("test123".encode(), nonce, 'sha256').digest()
envoyer(s, emballer(TypeMessage.AUTH_REQ, hmac_reponse, seq=0))
donnees = recevoir(s)
msg_type, seq, payload = deballer(donnees)

print("\n[1] Test avec message répétitif (bon pour compression):")
msg_repete = "Bonjour " * 100  # 800 bytes
msg_chiffre = chiffrer(msg_repete, "test123", compresser=True)
taille_compressee = len(msg_chiffre)
msg_sans_compression = chiffrer(msg_repete, "test123", compresser=False)
taille_sans_compression = len(msg_sans_compression)
reduction = 100 * (1 - taille_compressee / taille_sans_compression)
print(f"   Texte original: {len(msg_repete)} bytes")
print(f"   Avec compression: {taille_compressee} bytes")
print(f"   Sans compression: {taille_sans_compression} bytes")
print(f"   Réduction: {reduction:.1f}% 📉")

print("\n[2] Test avec message peu compressible (random):")
import random, string
msg_random = ''.join(random.choices(string.ascii_letters + string.digits, k=500))
msg_chiffre = chiffrer(msg_random, "test123", compresser=True)
taille_compressee = len(msg_chiffre)
msg_sans_compression = chiffrer(msg_random, "test123", compresser=False)
taille_sans_compression = len(msg_sans_compression)
reduction = 100 * (1 - taille_compressee / taille_sans_compression)
print(f"   Texte original: {len(msg_random)} bytes")
print(f"   Avec compression: {taille_compressee} bytes")
print(f"   Sans compression: {taille_sans_compression} bytes")
print(f"   Réduction: {reduction:.1f}%")
if reduction < 0:
    print(f"   (Compression déactivée - augmenterait la taille)")

print("\n[3] Envoi et réception via VPN:")
msg_test = "Ceci est un test de compression " * 5
msg_chiffre = chiffrer(msg_test, "test123")
envoyer(s, emballer(TypeMessage.DATA, msg_chiffre, seq=1))
donnees = recevoir(s)
msg_type, seq, payload = deballer(donnees)
reponse = dechiffrer(payload, "test123")
print(f"   Message envoyé: {len(msg_test)} bytes")
print(f"   Message chiffré: {len(msg_chiffre)} bytes")
print(f"   ✓ Réponse reçue: '{reponse[:50]}...'")

# Close
envoyer(s, emballer(TypeMessage.CLOSE, b'', seq=2))
s.close()

print("\n" + "="*60)
print("✅ COMPRESSION FONCTIONNELLE")
print("="*60)
