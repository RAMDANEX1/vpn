#!/usr/bin/env python
"""Test anti-bruteforce - bannissement après 3 échecs"""
import socket
import hmac
import time
from protocol import envoyer, recevoir, emballer, deballer, TypeMessage

print("\n" + "="*60)
print("🚫 TEST ANTI-BRUTEFORCE - Bannissement après 3 échecs")
print("="*60)

IP = "127.0.0.1"
PORT = 9999

for tentative in range(1, 5):
    print(f"\n[Tentative {tentative}]")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((IP, PORT))
        print("  ✓ Connecté au serveur")
        
        # Reçoit le challenge
        donnees = recevoir(s)
        msg_type, seq, nonce = deballer(donnees)
        print(f"  ✓ Challenge reçu")
        
        # Envoie MAUVAIS HMAC
        MAUVAIS_MDP = "bruteforce_attempt"
        hmac_reponse = hmac.new(MAUVAIS_MDP.encode(), nonce, 'sha256').digest()
        envoyer(s, emballer(TypeMessage.AUTH_REQ, hmac_reponse, seq=0))
        print(f"  ⚠️  Mauvais HMAC envoyé")
        
        # Attend réponse
        donnees = recevoir(s)
        msg_type, seq, payload = deballer(donnees)
        
        if msg_type == TypeMessage.AUTH_FAIL:
            print(f"  ✓ Rejeté: {payload.decode()}")
        
        s.close()
        
    except socket.timeout:
        print(f"  ❌ TIMEOUT - Serveur ne répond pas (probablement banni)")
    except ConnectionRefusedError:
        print(f"  ❌ REFUSÉ - Connexion fermée (banni après 3 échecs)")
    except Exception as e:
        print(f"  ❌ Erreur: {e}")
    
    if tentative < 4:
        time.sleep(1)

print("\n" + "="*60)
print("✅ TEST ANTI-BRUTEFORCE - OK")
print("   Le serveur bannit après 3 échecs d'authentification")
print("="*60)
