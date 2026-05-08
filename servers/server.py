# server.py — Serveur VPN éducatif (M3) - Multi-client avec authentication HMAC + Diffie-Hellman
import socket
import threading
import logging
import hmac
import os
import argparse
from itertools import count
from core.config import SERVEUR_IP, SERVEUR_PORT, MOT_DE_PASSE, TAILLE_BUFFER
from core.crypto import chiffrer, dechiffrer, dh_generate_key, dh_compute_shared_secret
from core.protocol import envoyer, recevoir, emballer, deballer, TypeMessage
from core.exceptions import ReplayAttackError
from core.exceptions import AuthenticationError, TunnelError

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
            ip_client = addr[0]
            
            # VÉRIFIER SI L'IP EST BANNIE (AVANT le handshake DH)
            if est_banni(ip_client):
                logging.warning(f"Refus {addr}: IP bannie")
                try:
                    envoyer(conn, emballer(TypeMessage.AUTH_FAIL, b"IP bannie"))
                except:
                    pass
                conn.close()
                continue
            
            # VÉRIFIER LIMITE DE CLIENTS (max_clients vraiment appliquée!)
            with lock:
                nb_connectes = len(clients_connectes)
            
            if nb_connectes >= max_clients:
                logging.warning(f"Refus {addr}: limite de {max_clients} clients atteinte ({nb_connectes} actifs)")
                try:
                    envoyer(conn, emballer(TypeMessage.AUTH_FAIL, b"Serveur plein"))
                except:
                    pass
                conn.close()
                continue
            
            # AJOUTER AU DICTIONNAIRE AVANT DE LANCER LE THREAD (évite race condition)
            with lock:
                clients_connectes[addr] = {"thread": None, "ip_virtuelle": None}
            
            # Créer et lancer le thread
            t = threading.Thread(target=gerer_client, args=(conn, addr), daemon=True)
            t.start()
            
            with lock:
                clients_connectes[addr]["thread"] = t
            
            logging.info(f"Client {addr} connecté — {len(clients_connectes)} client(s) actif(s)")
    
    except KeyboardInterrupt:
        logging.info("Arrêt du serveur")
    finally:
        s.close()


def dh_handshake_server(conn, addr) -> bytes:
    """
    Effectue l'échange de clé Diffie-Hellman avec le client.
    Retourne le salt dérivé du shared secret.
    """
    try:
        # Serveur génère sa paire de clés DH
        server_private, server_public = dh_generate_key()
        
        # Envoyer la clé publique au client (format: nombre entier en hex)
        server_public_hex = hex(server_public)[2:].encode()
        envoyer(conn, emballer(TypeMessage.REKEY, server_public_hex))
        logging.debug(f"[DH] Public key envoyée à {addr}")
        
        # Recevoir la clé publique du client
        donnees = recevoir(conn)
        msg_type, seq, client_public_hex = deballer(donnees)
        
        if msg_type != TypeMessage.REKEY:
            logging.warning(f"[DH] {addr} n'a pas envoyé sa clé publique")
            return None
        
        # Convertir la clé publique du client de hex à int
        client_public = int(client_public_hex.decode(), 16)
        
        # Calculer le shared secret (salt)
        shared_secret_salt = dh_compute_shared_secret(server_private, client_public)
        logging.info(f"[DH] Shared secret établi avec {addr}, salt={shared_secret_salt.hex()}")
        
        return shared_secret_salt
    
    except Exception as e:
        logging.error(f"[DH] Erreur handshake avec {addr}: {e}")
        return None


def gerer_client(conn, addr):
    """Gère la connexion d'un client."""
    ip_client = addr[0]
    
    # Initialiser les variables de transfert de fichier AVANT le try
    file_handle = None
    file_transfer_state = None
    file_name = None
    file_size = None
    file_received = 0
    
    try:
        # === ÉCHANGE DIFFIE-HELLMAN (unique key per session) ===
        # Note: Vérification du ban et du max faite AVANT dans demarrer_serveur()
        dh_salt = dh_handshake_server(conn, addr)
        if dh_salt is None:
            logging.warning(f"[DH] Échec de l'échange avec {addr}")
            return
        
        # Authentification avec challenge-response HMAC (avec le salt DH)
        if not authentifier(conn, addr, salt=dh_salt):
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
        seq_attendu = -1  # ← Start à -1 pour accepter seq=0 (premier message)
        while True:
            donnees = recevoir(conn)
            
            try:
                msg_type, seq, payload = deballer(donnees)
            except Exception as e:
                logging.error(f"Erreur deballing {addr}: {e}")
                break
            
            # === VÉRIFICATION DE SÉQUENCE (protection contre rejeu) ===
            if seq <= seq_attendu and msg_type != TypeMessage.CHALLENGE:
                # Note: CHALLENGE n'a pas de séquence garantie (challenge-response)
                logging.warning(f"[REPLAY] {addr} seq={seq} <= attendu={seq_attendu} (attaque par rejeu?)")
                raise ReplayAttackError(f"Séquence invalide: {seq} <= {seq_attendu}")
            
            seq_attendu = seq
            
            if msg_type == TypeMessage.CLOSE:
                logging.info(f"{addr} demande la fermeture")
                break
            
            if msg_type == TypeMessage.DATA:
                try:
                    message = dechiffrer(payload, MOT_DE_PASSE, salt=dh_salt)
                    logging.info(f"[{addr}] {message}")
                    
                    if message.lower() in ("exit", "quit"):
                        break
                    
                    # Répondre
                    reponse = f"Serveur a reçu : '{message}'"
                    reponse_chiffree = chiffrer(reponse, MOT_DE_PASSE, salt=dh_salt)
                    msg_reponse = emballer(TypeMessage.DATA, reponse_chiffree, seq=seq+1)
                    envoyer(conn, msg_reponse)
                    
                except ValueError as e:
                    logging.error(f"Erreur déchiffrement {addr}: {e}")
                    break
            
            elif msg_type == TypeMessage.FILE_START:
                # Début d'un transfert de fichier
                try:
                    meta = dechiffrer(payload, MOT_DE_PASSE, salt=dh_salt, return_bytes=False)
                    file_name, file_size_str = meta.split(':')
                    file_size = int(file_size_str)
                    file_received = 0
                    
                    file_path = os.path.join("fichiers_recus", file_name)
                    os.makedirs("fichiers_recus", exist_ok=True)
                    
                    file_handle = open(file_path, 'wb')
                    file_transfer_state = "receiving"
                    logging.info(f"[FILE] {addr} envoie '{file_name}' ({file_size} bytes)")
                except Exception as e:
                    logging.error(f"Erreur FILE_START {addr}: {e}")
                    file_transfer_state = None
            
            elif msg_type == TypeMessage.FILE_CHUNK:
                # Chunk de fichier
                if file_transfer_state == "receiving" and file_handle:
                    try:
                        chunk = dechiffrer(payload, MOT_DE_PASSE, salt=dh_salt, return_bytes=True)
                        file_handle.write(chunk)
                        file_received += len(chunk)
                        pourcentage = 100 * file_received // file_size if file_size > 0 else 0
                        logging.debug(f"[FILE] {file_received}/{file_size} bytes ({pourcentage}%)")
                    except Exception as e:
                        logging.error(f"Erreur FILE_CHUNK {addr}: {e}")
                        file_transfer_state = None
            
            elif msg_type == TypeMessage.FILE_END:
                # Fin du transfert
                if file_transfer_state == "receiving" and file_handle:
                    try:
                        file_handle.close()
                        logging.info(f"[FILE] '{file_name}' reçu ({file_received} bytes) de {addr}")
                        file_transfer_state = None
                    except Exception as e:
                        logging.error(f"Erreur FILE_END {addr}: {e}")
            
            elif msg_type == TypeMessage.PING:
                # Répondre avec PONG
                envoyer(conn, emballer(TypeMessage.PONG, b'', seq=seq+1))
                logging.debug(f"PING reçu de {addr}")

    except ConnectionError as e:
        logging.info(f"[DÉCONNEXION] {addr}: {e}")
    except Exception as e:
        logging.error(f"Erreur pour {addr}: {e}", exc_info=True)
    finally:
        # Nettoyer le fichier s'il était en cours de réception
        if file_handle:
            try:
                file_handle.close()
            except:
                pass
        
        conn.close()
        
        # Nettoyer l'entrée du client (robuste avec dict.pop)
        with lock:
            removed = clients_connectes.pop(addr, None)
            remaining = len(clients_connectes)
        
        if removed:
            logging.info(f"[FIN] {addr} déconnecté — {remaining} client(s) restant(s)")
        else:
            logging.warning(f"[FIN] {addr} n'était pas dans clients_connectes (race condition?) — {remaining} clients")


def authentifier(conn, addr, salt: bytes = None) -> bool:
    """
    Challenge-Response HMAC pour authentification sécurisée.
    Le mot de passe n'est jamais envoyé en clair.
    
    Args:
        salt: Salt DH pour dérivation de clé. Si None, utilise SALT_FIXE.
    """
    if salt is None:
        from core.crypto import SALT_FIXE
        salt = SALT_FIXE
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
