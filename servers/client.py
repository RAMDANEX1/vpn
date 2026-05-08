# client.py — Client VPN éducatif (M4) - Authentication HMAC sécurisée + Diffie-Hellman
import socket
import sys
import getpass
import hmac
import threading
import time
from core.config import SERVEUR_IP, SERVEUR_PORT, TAILLE_BUFFER
from core.crypto import chiffrer, dechiffrer, dh_generate_key, dh_compute_shared_secret
from core.protocol import envoyer, recevoir, emballer, deballer, TypeMessage
from core.exceptions import AuthenticationError, TunnelError


def dh_handshake_client(s) -> bytes:
    """
    Effectue l'échange de clé Diffie-Hellman avec le serveur.
    Retourne le salt dérivé du shared secret.
    """
    try:
        # Client génère sa paire de clés DH
        client_private, client_public = dh_generate_key()
        
        # Recevoir la clé publique du serveur
        donnees = recevoir(s)
        msg_type, seq, server_public_hex = deballer(donnees)
        
        if msg_type != TypeMessage.REKEY:
            print("[ERREUR] Serveur n'a pas envoyé sa clé publique DH")
            return None
        
        # Convertir la clé publique du serveur de hex à int
        server_public = int(server_public_hex.decode(), 16)
        
        # Envoyer la clé publique du client au serveur
        client_public_hex = hex(client_public)[2:].encode()
        envoyer(s, emballer(TypeMessage.REKEY, client_public_hex))
        print("[DH] Clé publique envoyée au serveur")
        
        # Calculer le shared secret (salt)
        shared_secret_salt = dh_compute_shared_secret(client_private, server_public)
        print(f"[DH] Shared secret établi, salt={shared_secret_salt.hex()}")
        
        return shared_secret_salt
    
    except Exception as e:
        print(f"[ERREUR] Erreur échange DH : {e}")
        return None


def se_connecter(serveur_ip=SERVEUR_IP, serveur_port=SERVEUR_PORT):
    """Se connecte au serveur VPN avec authentification HMAC + DH."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Demande du mot de passe à chaque connexion (non affiché à l'écran)
    mot_de_passe = getpass.getpass("Mot de passe > ").strip()
    if not mot_de_passe:
        print("[ERREUR] Mot de passe vide. Connexion annulée.")
        sys.exit(1)

    try:
        s.connect((serveur_ip, serveur_port))
        print(f"[CLIENT] Connecté à {serveur_ip}:{serveur_port}")
    except ConnectionRefusedError:
        print("[ERREUR] Impossible de joindre le serveur. Est-il lancé ?")
        print("         Vérifiez que server.py tourne dans un autre terminal.")
        sys.exit(1)

    # === ÉCHANGE DIFFIE-HELLMAN (unique key per session) ===
    dh_salt = dh_handshake_client(s)
    if dh_salt is None:
        print("[ERREUR] Échec de l'échange Diffie-Hellman")
        s.close()
        sys.exit(1)

    # Authentification avec challenge-response HMAC (avec le salt DH)
    try:
        if not authentifier(s, mot_de_passe, salt=dh_salt):
            print("[ERREUR] Authentification échouée (mot de passe incorrect).")
            s.close()
            sys.exit(1)
    except Exception as e:
        print(f"[ERREUR] Erreur d'authentification : {e}")
        s.close()
        sys.exit(1)

    print("[AUTH OK] Tunnel chiffré établi !")
    print("          Tapez vos messages ci-dessous (exit pour quitter)\n")

    # Démarrer un thread pour keepalive
    stop_event = threading.Event()
    t_ping = threading.Thread(target=keepalive, args=(s, stop_event), daemon=True)
    t_ping.start()

    # Boucle d'envoi de messages
    seq = 0
    try:
        while True:
            try:
                message = input("Toi > ")
            except (EOFError, KeyboardInterrupt):
                message = "exit"

            if message.lower() in ("exit", "quit"):
                # Envoyer un message CLOSE au serveur
                envoyer(s, emballer(TypeMessage.CLOSE, b'', seq=seq))
                break

            # Chiffrer et envoyer le message (avec salt DH)
            message_chiffre = chiffrer(message, mot_de_passe, salt=dh_salt)
            envoyer(s, emballer(TypeMessage.DATA, message_chiffre, seq=seq))
            seq += 1
    
    except Exception as e:
        print(f"[ERREUR] Erreur d'envoi : {e}")
    finally:
        stop_event.set()
        s.close()
        print("\n[FIN] Déconnecté")


def authentifier(s: socket.socket, mot_de_passe: str, salt: bytes = None) -> bool:
    """
    Effectue l'authentification challenge-response avec HMAC.
    Le mot de passe n'est jamais envoyé en clair.
    
    Args:
        salt: Salt DH pour dérivation de clé. Si None, utilise SALT_FIXE.
    """
    if salt is None:
        from core.crypto import SALT_FIXE
        salt = SALT_FIXE
    try:
        # Recevoir le challenge (nonce) du serveur
        donnees = recevoir(s)
        msg_type, seq, nonce = deballer(donnees)
        
        if msg_type != TypeMessage.CHALLENGE:
            print("[ERREUR] Le serveur n'a pas envoyé de challenge")
            return False
        
        # Calculer la réponse HMAC
        hmac_reponse = hmac.new(mot_de_passe.encode(), nonce+salt, 'sha256').digest()
        
        # Envoyer la réponse d'authentification
        envoyer(s, emballer(TypeMessage.AUTH_REQ, hmac_reponse, seq=0))
        
        # Attendre la confirmation du serveur
        donnees = recevoir(s)
        msg_type, seq, payload = deballer(donnees)
        
        if msg_type == TypeMessage.AUTH_OK:
            return True
        else:
            return False
    
    except Exception as e:
        print(f"[ERREUR] Erreur lors du challenge-response : {e}")
        return False


def keepalive(s: socket.socket, stop_event: threading.Event):
    """
    Envoie des PING au serveur toutes les 30 secondes pour maintenir la connexion.
    """
    seq = 0
    while not stop_event.is_set():
        time.sleep(30)
        try:
            envoyer(s, emballer(TypeMessage.PING, b'', seq=seq))
            seq += 1
        except OSError:
            break


if __name__ == "__main__":
    se_connecter()
