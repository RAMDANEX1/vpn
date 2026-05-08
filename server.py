# server.py — Serveur VPN éducatif (M3) - Multi-client avec authentication HMAC
import socket
import threading
import logging
import hmac
import os
import argparse
from itertools import count
from config import SERVEUR_IP, SERVEUR_PORT, MOT_DE_PASSE, TAILLE_BUFFER
from crypto import chiffrer, dechiffrer
from protocol import envoyer, recevoir, emballer, deballer, TypeMessage
from exceptions import AuthenticationError, TunnelError

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('vpn.log'),
        logging.StreamHandler()
    ]
)

# Variables globales
clients_connectes = {}
ip_pool = count(2)  # 10.8.0.2, 10.8.0.3, ...
lock = threading.Lock()
tentatives = {}  # {ip: {"count": 0, "ban_until": 0}}


def est_banni(ip: str) -> bool:
    """Vérifie si une IP est bannie."""
    import time
    if ip not in tentatives:
        return False
    info = tentatives[ip]
    if info["ban_until"] > time.time():
        return True
    return False


def enregistrer_echec(ip: str):
    """Enregistre un échec d'authentification et banni si nécessaire."""
    import time
    if ip not in tentatives:
        tentatives[ip] = {"count": 0, "ban_until": 0}
    
    tentatives[ip]["count"] += 1
    if tentatives[ip]["count"] >= 3:
        tentatives[ip]["ban_until"] = time.time() + 60
        logging.warning(f"IP {ip} bannie pour 60s (3 échecs d'authentification)")


def demarrer_serveur(host=SERVEUR_IP, port=SERVEUR_PORT, max_clients=10):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(max_clients)
    logging.info(f"Serveur en écoute sur {host}:{port}")
    logging.info(f"Capacité max : {max_clients} clients simultanés")

    try:
        while True:
            conn, addr = s.accept()
            # Créer un thread pour gérer ce client
            t = threading.Thread(target=gerer_client, args=(conn, addr), daemon=True)
            t.start()
            
            with lock:
                clients_connectes[addr] = {"thread": t, "ip_virtuelle": None}
            
            logging.info(f"Client {addr} connecté — {len(clients_connectes)} client(s) actif(s)")
    
    except KeyboardInterrupt:
        logging.info("Arrêt du serveur")
    finally:
        s.close()


def gerer_client(conn, addr):
    """Gère la connexion d'un client."""
    ip_client = addr[0]
    
    try:
        # Vérifier si l'IP est bannie
        if est_banni(ip_client):
            logging.warning(f"Tentative de connexion depuis IP bannie : {addr}")
            conn.close()
            return
        
        # Authentification avec challenge-response HMAC
        if not authentifier(conn, addr):
            enregistrer_echec(ip_client)
            logging.warning(f"Authentification échouée depuis {addr}")
            return
        
        # Authentification réussie
        with lock:
            tentatives[ip_client] = {"count": 0, "ban_until": 0}
        
        logging.info(f"[AUTH OK] {addr} authentifié — tunnel chiffré établi")
        
        # Attribuer une IP virtuelle
        ip_virtuelle = f"10.8.0.{next(ip_pool)}"
        with lock:
            clients_connectes[addr]["ip_virtuelle"] = ip_virtuelle
        
        logging.info(f"{addr} -> IP virtuelle {ip_virtuelle}")
        
        # Boucle d'échange de messages chiffrés
        seq_attendu = 0
        while True:
            donnees = recevoir(conn)
            
            try:
                msg_type, seq, payload = deballer(donnees)
            except Exception as e:
                logging.error(f"Erreur deballing {addr}: {e}")
                break
            
            if msg_type == TypeMessage.CLOSE:
                logging.info(f"{addr} demande la fermeture")
                break
            
            if msg_type == TypeMessage.DATA:
                try:
                    message = dechiffrer(payload, MOT_DE_PASSE)
                    logging.info(f"[{addr}] {message}")
                    
                    if message.lower() in ("exit", "quit"):
                        break
                    
                    # Répondre
                    reponse = f"Serveur a reçu : '{message}'"
                    reponse_chiffree = chiffrer(reponse, MOT_DE_PASSE)
                    msg_reponse = emballer(TypeMessage.DATA, reponse_chiffree, seq=seq+1)
                    envoyer(conn, msg_reponse)
                    
                except ValueError as e:
                    logging.error(f"Erreur déchiffrement {addr}: {e}")
                    break
            
            elif msg_type == TypeMessage.PING:
                # Répondre avec PONG
                envoyer(conn, emballer(TypeMessage.PONG, b'', seq=seq+1))
                logging.debug(f"PING reçu de {addr}")

    except ConnectionError as e:
        logging.info(f"[DÉCONNEXION] {addr}: {e}")
    except Exception as e:
        logging.error(f"Erreur pour {addr}: {e}", exc_info=True)
    finally:
        conn.close()
        with lock:
            if addr in clients_connectes:
                del clients_connectes[addr]
        logging.info(f"[FIN] {addr} déconnecté — {len(clients_connectes)} client(s) restant(s)")


def authentifier(conn, addr) -> bool:
    """
    Challenge-Response HMAC pour authentification sécurisée.
    Le mot de passe n'est jamais envoyé en clair.
    """
    try:
        # Envoyer un nonce aléatoire au client
        nonce = os.urandom(32)
        envoyer(conn, emballer(TypeMessage.CHALLENGE, nonce))
        
        # Attendre la réponse du client
        donnees = recevoir(conn)
        msg_type, seq, reponse_client = deballer(donnees)
        
        if msg_type != TypeMessage.AUTH_REQ:
            logging.warning(f"{addr} n'a pas répondu correctement au challenge")
            envoyer(conn, emballer(TypeMessage.AUTH_FAIL, b'Invalid response'))
            return False
        
        # Vérifier le HMAC
        hmac_attendu = hmac.new(MOT_DE_PASSE.encode(), nonce, 'sha256').digest()
        
        if not hmac.compare_digest(reponse_client, hmac_attendu):
            logging.warning(f"{addr} a envoyé un HMAC incorrect")
            envoyer(conn, emballer(TypeMessage.AUTH_FAIL, b'Wrong password'))
            return False
        
        # Authentification réussie
        envoyer(conn, emballer(TypeMessage.AUTH_OK, b''))
        return True
    
    except Exception as e:
        logging.error(f"Erreur d'authentification pour {addr}: {e}")
        return False


def parse_args():
    """Parse les arguments en ligne de commande."""
    p = argparse.ArgumentParser(description="Serveur VPN éducatif")
    p.add_argument('--host', default=SERVEUR_IP, help='IP d\'écoute')
    p.add_argument('--port', type=int, default=SERVEUR_PORT, help='Port TCP')
    p.add_argument('--max-clients', type=int, default=10, help='Max clients simultanés')
    p.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING'])
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    logging.getLogger().setLevel(args.log_level)
    demarrer_serveur(host=args.host, port=args.port, max_clients=args.max_clients)
