# crypto.py — Module de chiffrement AES-256-GCM (M2)
import os
import hashlib
import zlib
from Crypto.Cipher import AES


SALT_FIXE = b'vpn_educatif_l2_2026'  # sel fixe partagé


def _obtenir_cle(mot_de_passe: str, salt: bytes = SALT_FIXE) -> bytes:
    """
    Dérive une clé AES-256 avec PBKDF2-HMAC-SHA256 (100 000 itérations).
    Beaucoup plus sûr qu'un simple SHA-256 sans sel.
    """
    return hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=mot_de_passe.encode('utf-8'),
        salt=salt,
        iterations=100_000,
        dklen=32
    )


def chiffrer(message: str, mot_de_passe: str, compresser: bool = True) -> bytes:
    """
    Chiffre un message texte avec AES-256-GCM, avec compression optionnelle.
    Retourne un paquet bytes : flag_compression(1) + IV(12) + message_chiffré + tag(16)
    """
    cle = _obtenir_cle(mot_de_passe)
    iv = os.urandom(12)  # 12 bytes aléatoires (différent à chaque fois)
    
    payload = message.encode('utf-8')
    flag_compression = b'\x01' if compresser else b'\x00'
    
    if compresser:
        payload_compresse = zlib.compress(payload, level=6)
        # Utiliser la compression seulement si elle réduit la taille
        if len(payload_compresse) < len(payload):
            payload = payload_compresse
        else:
            flag_compression = b'\x00'
    
    cipher = AES.new(cle, AES.MODE_GCM, nonce=iv)
    chiffre, tag = cipher.encrypt_and_digest(payload)
    return flag_compression + iv + chiffre + tag  # tout dans un seul paquet


def dechiffrer(donnees: bytes, mot_de_passe: str) -> str:
    """
    Déchiffre un paquet produit par chiffrer().
    Gère automatiquement la décompression si nécessaire.
    Lève ValueError si le paquet a été modifié (sécurité !)
    """
    cle = _obtenir_cle(mot_de_passe)
    flag_compression = donnees[0:1]
    iv = donnees[1:13]  # les 12 bytes après le flag = IV
    chiffre = donnees[13:-16]  # le milieu = message chiffré
    tag = donnees[-16:]  # les 16 derniers bytes = tag
    cipher = AES.new(cle, AES.MODE_GCM, nonce=iv)
    payload = cipher.decrypt_and_verify(chiffre, tag)
    
    if flag_compression == b'\x01':
        payload = zlib.decompress(payload)
    
    return payload.decode('utf-8')
