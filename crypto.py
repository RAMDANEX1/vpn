"""Chiffrement AES-GCM 256 pour mini-vpn.

API publique:
- chiffrer(message, cle)
- dechiffrer(token, cle)
"""

from __future__ import annotations

import base64
import hashlib

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


NONCE_SIZE = 12
TAG_SIZE = 16


class CryptoManager:
    """Gestionnaire de chiffrement AES-GCM 256 pour messages texte."""

    def __init__(self, cle: str):
        self._key = hashlib.sha256(cle.encode("utf-8")).digest()

    def chiffrer(self, message: str) -> str:
        """Chiffre un message UTF-8 en AES-GCM-256 et renvoie un token base64url."""
        nonce = get_random_bytes(NONCE_SIZE)
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode("utf-8"))
        paquet = nonce + tag + ciphertext
        return base64.urlsafe_b64encode(paquet).decode("ascii")

    def dechiffrer(self, token: str) -> str:
        """Dechiffre un token base64url AES-GCM-256 et valide son authentification."""
        try:
            paquet = base64.urlsafe_b64decode(token.encode("ascii"))
        except Exception as exc:  # pragma: no cover - defensive parsing
            raise ValueError("Token invalide") from exc

        min_size = NONCE_SIZE + TAG_SIZE
        if len(paquet) < min_size:
            raise ValueError("Token trop court")

        nonce = paquet[:NONCE_SIZE]
        tag = paquet[NONCE_SIZE:min_size]
        ciphertext = paquet[min_size:]

        try:
            cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_SIZE)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as exc:
            raise ValueError("Cle incorrecte ou donnees alterees") from exc

        return plaintext.decode("utf-8")


def chiffrer(message: str, cle: str) -> str:
    """Wrapper de compatibilite vers CryptoManager."""
    return CryptoManager(cle).chiffrer(message)


def dechiffrer(token: str, cle: str) -> str:
    """Wrapper de compatibilite vers CryptoManager."""
    return CryptoManager(cle).dechiffrer(token)
