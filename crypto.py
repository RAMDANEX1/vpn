# crypto.py — Module de chiffrement AES-256-GCM (M2)
import os
import hashlib
from Crypto.Cipher import AES


def _obtenir_cle(mot_de_passe: str) -> bytes:
    """Transforme un mot de passe en clé de 32 bytes pour AES-256."""
    return hashlib.sha256(mot_de_passe.encode()).digest()


def chiffrer(message: str, mot_de_passe: str) -> bytes:
    """
    Chiffre un message texte avec AES-256-GCM.
    Retourne un paquet bytes : IV(12) + message_chiffré + tag(16)
    """
    cle    = _obtenir_cle(mot_de_passe)
    iv     = os.urandom(12)                          # 12 bytes aléatoires (différent à chaque fois)
    cipher = AES.new(cle, AES.MODE_GCM, nonce=iv)
    chiffre, tag = cipher.encrypt_and_digest(message.encode())
    return iv + chiffre + tag                        # tout dans un seul paquet


def dechiffrer(donnees: bytes, mot_de_passe: str) -> str:
    """
    Déchiffre un paquet produit par chiffrer().
    Lève ValueError si le paquet a été modifié (sécurité !)
    """
    cle     = _obtenir_cle(mot_de_passe)
    iv      = donnees[:12]    # les 12 premiers bytes = IV
    chiffre = donnees[12:-16] # le milieu = message chiffré
    tag     = donnees[-16:]   # les 16 derniers bytes = tag
    cipher  = AES.new(cle, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(chiffre, tag).decode()
