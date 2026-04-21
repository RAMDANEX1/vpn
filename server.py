# server.py — Serveur VPN éducatif (M3)
import socket
from config import SERVEUR_IP, SERVEUR_PORT, MOT_DE_PASSE, TAILLE_BUFFER
from crypto import chiffrer, dechiffrer


def demarrer_serveur():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # évite "port déjà utilisé"
    s.bind((SERVEUR_IP, SERVEUR_PORT))
    s.listen(1)
    print(f"[SERVEUR] En écoute sur {SERVEUR_IP}:{SERVEUR_PORT}")
    print("[SERVEUR] Attente d'un client... (Ctrl+C pour arrêter)")

    while True:
        conn, addr = s.accept()
        print(f"\n[CONNEXION] Client connecté depuis {addr}")
        gerer_client(conn, addr)


def gerer_client(conn, addr):
    try:
        # Étape 1 : vérifier le mot de passe (envoyé en clair, amélioration possible)
        mdp_recu = conn.recv(TAILLE_BUFFER).decode()
        if mdp_recu != MOT_DE_PASSE:
            print(f"[REFUS] Mauvais mot de passe depuis {addr}")
            conn.send(b"REFUS")
            conn.close()
            return

        conn.send(b"OK")
        print(f"[AUTH OK] {addr} authentifié — tunnel chiffré établi")

        # Étape 2 : boucle d'échange de messages chiffrés
        while True:
            donnees = conn.recv(TAILLE_BUFFER)
            if not donnees:
                break

            message = dechiffrer(donnees, MOT_DE_PASSE)
            print(f"[REÇU] {message}")

            if message.lower() in ("exit", "quit"):
                break

            reponse = f"Serveur a reçu : '{message}'"
            conn.send(chiffrer(reponse, MOT_DE_PASSE))
            print(f"[ENVOYÉ] réponse chiffrée")

    except ValueError:
        print(f"[ERREUR] Paquet corrompu depuis {addr} — connexion fermée")
    except ConnectionResetError:
        print(f"[DÉCONNEXION] {addr} s'est déconnecté")
    finally:
        conn.close()
        print(f"[FIN] Connexion avec {addr} terminée\n")


if __name__ == "__main__":
    demarrer_serveur()
