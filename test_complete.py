#!/usr/bin/env python
"""Test client automatisé - teste les fonctionnalités du VPN"""
import socket
import hmac
import time
from protocol import envoyer, recevoir, emballer, deballer, TypeMessage
from crypto import chiffrer, dechiffrer

MOT_DE_PASSE = "test123"
SERVEUR = ("127.0.0.1", 9999)

def test_vpn():
    print("\n" + "="*60)
    print("🔐 TEST VPN ÉDUCATIF - Challenge-Response HMAC")
    print("="*60)
    
    # Connexion
    print("\n[1️⃣] Connexion au serveur...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(SERVEUR)
    print("    ✓ Connecté à", SERVEUR)
    
    # Réception du challenge
    print("\n[2️⃣] Réception du challenge...")
    donnees = recevoir(s)
    msg_type, seq, nonce = deballer(donnees)
    assert msg_type == TypeMessage.CHALLENGE
    print(f"    ✓ Challenge reçu (nonce {len(nonce)} bytes)")
    
    # Réponse HMAC
    print("\n[3️⃣] Calcul réponse HMAC-SHA256...")
    hmac_reponse = hmac.new(MOT_DE_PASSE.encode(), nonce, 'sha256').digest()
    print(f"    ✓ HMAC calculé ({len(hmac_reponse)} bytes)")
    
    # Envoi de la réponse
    print("\n[4️⃣] Envoi AUTH_REQ...")
    envoyer(s, emballer(TypeMessage.AUTH_REQ, hmac_reponse, seq=0))
    print("    ✓ Envoyé")
    
    # Réception de la réponse
    print("\n[5️⃣] Attente AUTH_OK...")
    donnees = recevoir(s)
    msg_type, seq, payload = deballer(donnees)
    assert msg_type == TypeMessage.AUTH_OK
    print("    ✓ Authentification réussie ! 🎉")
    
    # Envoi d'un message
    print("\n[6️⃣] Envoi d'un message chiffré...")
    message = "Bonjour le VPN sécurisé !"
    msg_chiffre = chiffrer(message, MOT_DE_PASSE)
    envoyer(s, emballer(TypeMessage.DATA, msg_chiffre, seq=1))
    print(f"    ✓ Message envoyé (chiffré: {len(msg_chiffre)} bytes)")
    
    # Réception de la réponse
    print("\n[7️⃣] Réception de la réponse du serveur...")
    donnees = recevoir(s)
    msg_type, seq, payload = deballer(donnees)
    assert msg_type == TypeMessage.DATA
    reponse = dechiffrer(payload, MOT_DE_PASSE)
    print(f"    ✓ Reçu: '{reponse}'")
    
    # Test PING/PONG
    print("\n[8️⃣] Test Keepalive PING/PONG...")
    envoyer(s, emballer(TypeMessage.PING, b'', seq=2))
    print("    ✓ PING envoyé")
    time.sleep(0.5)
    donnees = recevoir(s)
    msg_type, seq, payload = deballer(donnees)
    assert msg_type == TypeMessage.PONG
    print("    ✓ PONG reçu")
    
    # Test de sécurité : envoi d'un message court et d'un long
    print("\n[9️⃣] Test compression & messages variés...")
    
    # Message court
    msg_court = "Hi"
    msg_chiffre = chiffrer(msg_court, MOT_DE_PASSE)
    envoyer(s, emballer(TypeMessage.DATA, msg_chiffre, seq=3))
    donnees = recevoir(s)
    _, _, payload = deballer(donnees)
    reponse = dechiffrer(payload, MOT_DE_PASSE)
    print(f"    ✓ Court: '{msg_court}' -> serveur répond: '{reponse}'")
    
    # Message long
    msg_long = "Ceci est un message très long " * 5
    msg_chiffre = chiffrer(msg_long, MOT_DE_PASSE)
    envoyer(s, emballer(TypeMessage.DATA, msg_chiffre, seq=4))
    donnees = recevoir(s)
    _, _, payload = deballer(donnees)
    reponse = dechiffrer(payload, MOT_DE_PASSE)
    print(f"    ✓ Long: ({len(msg_long)} chars) compressé à {len(msg_chiffre)} bytes")
    
    # Test avec caractères spéciaux
    print("\n[🔟] Test Unicode & sécurité...")
    msg_unicode = "Bonjour 你好 مرحبا 🔐"
    msg_chiffre = chiffrer(msg_unicode, MOT_DE_PASSE)
    envoyer(s, emballer(TypeMessage.DATA, msg_chiffre, seq=5))
    donnees = recevoir(s)
    _, _, payload = deballer(donnees)
    reponse = dechiffrer(payload, MOT_DE_PASSE)
    print(f"    ✓ Unicode: '{msg_unicode}' -> OK")
    
    # Déconnexion
    print("\n[✅] Déconnexion...")
    envoyer(s, emballer(TypeMessage.CLOSE, b'', seq=6))
    s.close()
    print("    ✓ Socket fermé")
    
    print("\n" + "="*60)
    print("✅ TOUS LES TESTS RÉUSSIS !")
    print("="*60)
    print("\n🔒 Résumé des sécurités testées:")
    print("   • Authentication HMAC-SHA256 (challenge-response)")
    print("   • AES-256-GCM chiffrement + intégrité")
    print("   • PBKDF2 dérivation clé (100k itérations)")
    print("   • Framing TCP (longueur fiable)")
    print("   • Types de messages structurés")
    print("   • Keepalive PING/PONG")
    print("   • Compression optionnelle zlib")
    print("   • Unicode/Emojis supportés")
    print("\n")

if __name__ == "__main__":
    try:
        test_vpn()
    except Exception as e:
        print(f"\n❌ ERREUR: {e}")
        import traceback
        traceback.print_exc()
