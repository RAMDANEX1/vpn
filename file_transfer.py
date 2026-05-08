# file_transfer.py — Transfert sécurisé de fichiers via VPN
import os
import socket
from protocol import envoyer, recevoir, emballer, deballer, TypeMessage
from crypto import chiffrer, dechiffrer


def envoyer_fichier(sock: socket.socket, chemin: str, mot_de_passe: str):
    """
    Envoie un fichier au serveur via le tunnel chiffré.
    
    Protocole:
    1. FILE_START : métadonnées (nom + taille)
    2. FILE_CHUNK x N : morceaux du fichier
    3. FILE_END : confirmation
    """
    if not os.path.exists(chemin):
        print(f"[ERREUR] Fichier introuvable : {chemin}")
        return False
    
    nom = os.path.basename(chemin)
    taille = os.path.getsize(chemin)
    CHUNK_SIZE = 4096
    
    try:
        # Annoncer le fichier
        meta = f"{nom}:{taille}".encode()
        meta_chiffre = chiffrer(meta.decode(), mot_de_passe)
        envoyer(sock, emballer(TypeMessage.FILE_START, meta_chiffre))
        print(f"[FICHIER] Envoi de '{nom}' ({taille} bytes)...")
        
        # Envoyer en morceaux
        with open(chemin, 'rb') as f:
            envoye = 0
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                chunk_chiffre = chiffrer(chunk.decode('utf-8', errors='ignore'), mot_de_passe)
                envoyer(sock, emballer(TypeMessage.FILE_CHUNK, chunk_chiffre))
                envoye += len(chunk)
                pourcentage = 100 * envoye // taille
                print(f"\r[FICHIER] {envoye}/{taille} bytes ({pourcentage}%)", end='', flush=True)
        
        # Confirmer l'envoi
        envoyer(sock, emballer(TypeMessage.FILE_END, b''))
        print(f"\n[FICHIER] '{nom}' envoyé avec succès")
        return True
    
    except Exception as e:
        print(f"[ERREUR] Erreur lors de l'envoi du fichier : {e}")
        return False


def recevoir_fichier(sock: socket.socket, mot_de_passe: str, dossier_destination: str = ".") -> bool:
    """
    Reçoit un fichier du serveur via le tunnel chiffré.
    Le fichier est sauvegardé dans dossier_destination.
    """
    try:
        # Recevoir les métadonnées
        donnees = recevoir(sock)
        msg_type, seq, payload = deballer(donnees)
        
        if msg_type != TypeMessage.FILE_START:
            print("[ERREUR] Protocole de transfert invalide")
            return False
        
        meta = dechiffrer(payload, mot_de_passe)
        nom, taille_str = meta.split(':')
        taille = int(taille_str)
        
        chemin_dest = os.path.join(dossier_destination, nom)
        print(f"[FICHIER] Réception de '{nom}' ({taille} bytes)...")
        
        # Recevoir le fichier
        with open(chemin_dest, 'wb') as f:
            recu = 0
            while recu < taille:
                donnees = recevoir(sock)
                msg_type, seq, payload = deballer(donnees)
                
                if msg_type == TypeMessage.FILE_END:
                    break
                
                if msg_type == TypeMessage.FILE_CHUNK:
                    chunk = dechiffrer(payload, mot_de_passe).encode('utf-8', errors='ignore')
                    f.write(chunk)
                    recu += len(chunk)
                    pourcentage = 100 * recu // taille
                    print(f"\r[FICHIER] {recu}/{taille} bytes ({pourcentage}%)", end='', flush=True)
        
        print(f"\n[FICHIER] '{nom}' reçu avec succès dans {dossier_destination}")
        return True
    
    except Exception as e:
        print(f"[ERREUR] Erreur lors de la réception du fichier : {e}")
        return False
