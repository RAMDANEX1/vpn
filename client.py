# client.py — Client VPN éducatif (M4)
import socket
import sys
import getpass
from config import SERVEUR_IP, SERVEUR_PORT, TAILLE_BUFFER
from crypto import chiffrer, dechiffrer


def se_connecter():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Demande du mot de passe à chaque connexion (non affiché à l'écran)
    mot_de_passe = getpass.getpass("Mot de passe > ").strip()
    if not mot_de_passe:
        print("[ERREUR] Mot de passe vide. Connexion annulée.")
        sys.exit(1)

    try:
        s.connect((SERVEUR_IP, SERVEUR_PORT))
        print(f"[CLIENT] Connecté à {SERVEUR_IP}:{SERVEUR_PORT}")
    except ConnectionRefusedError:
        print("[ERREUR] Impossible de joindre le serveur. Est-il lancé ?")
        print("         Vérifiez que server.py tourne dans un autre terminal.")
        sys.exit(1)

    # Étape 1 : s'authentifier
    s.send(mot_de_passe.encode())
    reponse = s.recv(TAILLE_BUFFER).decode()

    if reponse != "OK":
        print("[ERREUR] Mot de passe incorrect. Connexion refusée.")
        s.close()
        sys.exit(1)

    print("[AUTH OK] Tunnel chiffré établi !")
    print("          Tapez vos messages ci-dessous (exit pour quitter)\n")

    # Étape 2 : boucle d'envoi de messages
    while True:
        try:
            message = input("Toi > ")
        except (EOFError, KeyboardInterrupt):
            message = "exit"

        if message.lower() in ("exit", "quit"):
            s.send(chiffrer("EXIT", mot_de_passe))
            break

        s.send(chiffrer(message, mot_de_passe))

        reponse_chiffree = s.recv(TAILLE_BUFFER)
        reponse = dechiffrer(reponse_chiffree, mot_de_passe)
        print(f"Serveur > {reponse}\n")

    s.close()
    print("[CLIENT] Déconnecté.")


if __name__ == "__main__":
    se_connecter()
