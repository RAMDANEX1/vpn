# exceptions.py — Exceptions personnalisées pour le VPN

class VPNException(Exception):
    """Exception de base du protocole VPN."""
    pass


class AuthenticationError(VPNException):
    """Échec d'authentification."""
    pass


class PacketError(VPNException):
    """Paquet mal formé ou corrompu."""
    pass


class TunnelError(VPNException):
    """Erreur sur le tunnel chiffré."""
    pass


class ReplayAttackError(VPNException):
    """Paquet rejoué détecté."""
    pass
