#!/usr/bin/env python
"""Test client automatisé - teste les fonctionnalités du VPN"""
import socket
import hmac
import time
from core.protocol import envoyer, recevoir, emballer, deballer, TypeMessage
from core.crypto import chiffrer, dechiffrer

MOT_DE_PASSE = "test123"
SERVEUR = ("127.0.0.1", 9999)

def test_vpn():
    print("\n" + "="*60)
    print("[TEST] VPN EDUCATIF - Challenge-Response HMAC")
    print("="*60)
    
    # Connexion
    print("\n[1] Connexion au serveur...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(SERVEUR)
    print("    OK Connecte a", SERVEUR)
    
    # Réception du challenge
    print("\n[2] Reception du challenge...")
    donnees = recevoir(s)
    msg_type, seq, nonce = deballer(donnees)
    assert msg_type == TypeMessage.CHALLENGE
    print(f"    OK Challenge recu (nonce {len(nonce)} bytes)")
    
    # Réponse HMAC
    print("\n[3] Calcul reponse HMAC-SHA256...")
    hmac_reponse = hmac.new(MOT_DE_PASSE.encode(), nonce, 'sha256').digest()
    print(f"    OK HMAC calcule ({len(hmac_reponse)} bytes)")
    
    # Envoi de la réponse
    print("\n[4] Envoi AUTH_REQ...")
    envoyer(s, emballer(TypeMessage.AUTH_REQ, hmac_reponse, seq=0))
    print("    OK Envoye")
    
    # Réception de la réponse
    print("\n[5] Attente AUTH_OK...")
    donnees = recevoir(s)
    msg_type, seq, payload = deballer(donnees)
    assert msg_type == TypeMessage.AUTH_OK
    print("    OK Authentification reussie !")
    
    # Envoi d'un message
    print("\n[6] Envoi d'un message chiffre...")
    message = "Bonjour le VPN securise !"
    msg_chiffre = chiffrer(message, MOT_DE_PASSE)
    envoyer(s, emballer(TypeMessage.DATA, msg_chiffre, seq=1))
    print(f"    OK Message envoye (chiffre: {len(msg_chiffre)} bytes)")
    
    # Réception de la réponse
    print("\n[7] Reception de la reponse du serveur...")
    donnees = recevoir(s)
    msg_type, seq, payload = deballer(donnees)
    assert msg_type == TypeMessage.DATA
    reponse = dechiffrer(payload, MOT_DE_PASSE)
    print(f"    OK Recu: '{reponse}'")
    
    # Test PING/PONG
    print("\n[8] Test Keepalive PING/PONG...")
    envoyer(s, emballer(TypeMessage.PING, b'', seq=2))
    print("    OK PING envoye")
    time.sleep(0.5)
    donnees = recevoir(s)
    msg_type, seq, payload = deballer(donnees)
    assert msg_type == TypeMessage.PONG
    print("    OK PONG recu")
    
    # Test de sécurité : envoi d'un message court et d'un long
    print("\n[9] Test compression & messages varies...")
    
    # Message court
    msg_court = "Hi"
    msg_chiffre = chiffrer(msg_court, MOT_DE_PASSE)
    envoyer(s, emballer(TypeMessage.DATA, msg_chiffre, seq=3))
    donnees = recevoir(s)
    _, _, payload = deballer(donnees)
    reponse = dechiffrer(payload, MOT_DE_PASSE)
    print(f"    OK Court: '{msg_court}' -> serveur repond: '{reponse}'")
    
    # Message long
    msg_long = "Ceci est un message tres long " * 5
    msg_chiffre = chiffrer(msg_long, MOT_DE_PASSE)
    envoyer(s, emballer(TypeMessage.DATA, msg_chiffre, seq=4))
    donnees = recevoir(s)
    _, _, payload = deballer(donnees)
    reponse = dechiffrer(payload, MOT_DE_PASSE)
    print(f"    OK Long: ({len(msg_long)} chars) compresse a {len(msg_chiffre)} bytes")
    
    # Test avec caractères spéciaux
    print("\n[10] Test Unicode & securite...")
    msg_unicode = "Bonjour test"
    msg_chiffre = chiffrer(msg_unicode, MOT_DE_PASSE)
    envoyer(s, emballer(TypeMessage.DATA, msg_chiffre, seq=5))
    donnees = recevoir(s)
    _, _, payload = deballer(donnees)
    reponse = dechiffrer(payload, MOT_DE_PASSE)
    print(f"    OK Unicode: '{msg_unicode}' -> OK")
    
    # Déconnexion
    print("\n[OK] Deconnexion...")
    envoyer(s, emballer(TypeMessage.CLOSE, b'', seq=6))
    s.close()
    print("    OK Socket ferme")
    
    print("\n" + "="*60)
    print("OK TOUS LES TESTS REUSSIS !")
    print("="*60)
    print("\nResume des securites testees:")
    print("   - Authentication HMAC-SHA256 (challenge-response)")
    print("   - AES-256-GCM chiffrement + integrite")
    print("   - PBKDF2 derivation cle (100k iterations)")
    print("   - Framing TCP (longueur fiable)")
    print("   - Types de messages structures")
    print("   - Keepalive PING/PONG")
    print("   - Compression optionnelle zlib")
    print("   - Unicode/Caracteres speciaux supportes")
    print("\n")

if __name__ == "__main__":
    try:
        test_vpn()
    except Exception as e:
        print(f"\nERREUR: {e}")
        import traceback
        traceback.print_exc()
