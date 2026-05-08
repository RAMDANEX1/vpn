# crypto.py — Module de chiffrement AES-256-GCM (M2)
import os
import hashlib
import zlib
from Crypto.Cipher import AES

# Diffie-Hellman simplifié (RFC 3526 - 2048-bit MODP Group 14)
# p = grand nombre premier, g = base
DH_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
DH_G = 2

# Salt par défaut pour backward compatibility (chiffrement sans DH)
SALT_FIXE = b'vpn_educatif_l2_2026'


def _obtenir_cle(mot_de_passe: str, salt: bytes = SALT_FIXE) -> bytes:
    """
    Dérive une clé AES-256 avec PBKDF2-HMAC-SHA256 (100 000 itérations).
    
    Par défaut utilise SALT_FIXE pour backward compatibility.
    Pour les nouvelles sessions, passer salt unique issu de Diffie-Hellman.
    """
    return hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=mot_de_passe.encode('utf-8'),
        salt=salt,
        iterations=100_000,
        dklen=32
    )


def chiffrer(message: str | bytes, mot_de_passe: str, compresser: bool = True, salt: bytes = None) -> bytes:
    """
    Chiffre un message (texte ou binaire) avec AES-256-GCM, avec compression optionnelle.
    Retourne un paquet bytes : flag_compression(1) + IV(12) + message_chiffré + tag(16) ( total = 29 bytes + taille message chiffré)
    
    Args:
        message: str ou bytes à chiffrer. Si str, encodé en UTF-8. Si bytes, utilisé directement.
        salt: Salt pour PBKDF2. Si None, utilise SALT_FIXE (backward compat).
              Si fourni, utilise le salt issu de Diffie-Hellman.
    """
    if salt is None:
        salt = SALT_FIXE
    cle = _obtenir_cle(mot_de_passe, salt=salt)
    iv = os.urandom(12)  # 12 bytes aléatoires (différent à chaque fois)
    
    # Convertir message en bytes s'il est str
    if isinstance(message, str):
        payload = message.encode('utf-8')
    else:
        payload = message
    
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


def dechiffrer(donnees: bytes, mot_de_passe: str, salt: bytes = None, return_bytes: bool = False) -> str | bytes:
    """
    Déchiffre un paquet produit par chiffrer().
    Gère automatiquement la décompression si nécessaire.
    Lève ValueError si le paquet a été modifié (sécurité !)
    
    Args:
        salt: Salt pour PBKDF2. Si None, utilise SALT_FIXE (backward compat).
              Si fourni, utilise le salt issu de Diffie-Hellman.
        return_bytes: Si True, retourne les bytes bruts. Si False (défaut), décode en UTF-8.
    """
    if salt is None:
        salt = SALT_FIXE
    cle = _obtenir_cle(mot_de_passe, salt=salt)
    flag_compression = donnees[0:1]
    iv = donnees[1:13]  # les 12 bytes après le flag = IV
    chiffre = donnees[13:-16]  # le milieu = message chiffré
    tag = donnees[-16:]  # les 16 derniers bytes = tag
    cipher = AES.new(cle, AES.MODE_GCM, nonce=iv)
    payload = cipher.decrypt_and_verify(chiffre, tag)
    
    if flag_compression == b'\x01':
        payload = zlib.decompress(payload)
    
    if return_bytes:
        return payload
    else:
        return payload.decode('utf-8')


# ========== DIFFIE-HELLMAN (Échange de clé sécurisé) ==========

def dh_generate_key() -> tuple:
    """
    Génère une paire de clés Diffie-Hellman.
    Retourne : (private_key_int, public_key_int)
    """
    # Private key : nombre aléatoire entre 2 et p-2
    private_key = int.from_bytes(os.urandom(256), byteorder='big') % (DH_P - 2) + 2
    # Public key : g^private mod p
    public_key = pow(DH_G, private_key, DH_P)
    return private_key, public_key


def dh_compute_shared_secret(private_key: int, peer_public_key: int) -> bytes:
    """
    Calcule le secret partagé : peer_public^private mod p
    Retourne : 16 bytes (salt unique pour cette session)
    """
    # Shared secret : peer_public^private mod p
    shared_secret_int = pow(peer_public_key, private_key, DH_P)
    # Convertir en bytes et hash pour obtenir 16 bytes de salt
    shared_secret_bytes = shared_secret_int.to_bytes(256, byteorder='big')
    return hashlib.sha256(shared_secret_bytes).digest()[:16]


def dh_derive_session_key(shared_secret_salt: bytes, mot_de_passe: str) -> bytes:
    """
    Dérive une clé AES-256 unique pour cette session.
    Utilise le salt DH + mot de passe partagé.
    """
    return _obtenir_cle(mot_de_passe, salt=shared_secret_salt)
