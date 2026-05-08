# protocol.py — Framing TCP et types de messages

import struct
import socket
from enum import IntEnum
from exceptions import PacketError


class TypeMessage(IntEnum):
    """Types de messages du protocole VPN."""
    HELLO      = 0x01
    CHALLENGE  = 0x02
    AUTH_REQ   = 0x03
    AUTH_OK    = 0x04
    AUTH_FAIL  = 0x05
    DATA       = 0x10
    FILE_START = 0x11
    FILE_CHUNK = 0x12
    FILE_END   = 0x13
    PING       = 0x20
    PONG       = 0x21
    REKEY      = 0x30
    CLOSE      = 0xFF


HEADER_SIZE = 9  # Format : [ type(1) | seq(4) | longueur(4) ]


def emballer(type_msg: TypeMessage, payload: bytes, seq: int = 0) -> bytes:
    """
    Emballe un message avec son header.
    Format : [ type(1) | seq(4) | longueur(4) | payload ]
    """
    header = struct.pack('>BII', int(type_msg), seq, len(payload))
    return header + payload


def deballer(data: bytes) -> tuple:
    """
    Déplie un message.
    Retourne : (type_msg, seq, payload)
    """
    if len(data) < HEADER_SIZE:
        raise PacketError(f"Paquet trop court : {len(data)} < {HEADER_SIZE}")
    
    type_msg, seq, longueur = struct.unpack('>BII', data[:HEADER_SIZE])
    payload = data[HEADER_SIZE:HEADER_SIZE + longueur]
    
    if len(payload) != longueur:
        raise PacketError(f"Payload incomplet : {len(payload)} != {longueur}")
    
    return TypeMessage(type_msg), seq, payload


def envoyer(sock: socket.socket, data: bytes) -> None:
    """
    Envoie data précédée de sa longueur sur 4 bytes (big-endian).
    Garantit que la totalité des données est envoyée.
    """
    header = struct.pack('>I', len(data))
    sock.sendall(header + data)


def recevoir(sock: socket.socket) -> bytes:
    """
    Reçoit exactement un message complet.
    Lève ConnectionError si la connexion est fermée prématurément.
    """
    # Lire les 4 bytes de longueur
    header = _lire_exactement(sock, 4)
    longueur = struct.unpack('>I', header)[0]
    # Lire exactement longueur bytes
    return _lire_exactement(sock, longueur)


def _lire_exactement(sock: socket.socket, n: int) -> bytes:
    """
    Lit exactement n bytes depuis le socket.
    Lève ConnectionError si la connexion est fermée avant n bytes.
    """
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connexion fermée prématurément")
        buf += chunk
    return buf
