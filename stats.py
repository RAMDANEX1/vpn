# stats.py — Statistiques de session
import time
from dataclasses import dataclass, field


@dataclass
class SessionStats:
    """Suivi des statistiques de session VPN."""
    debut: float = field(default_factory=time.time)
    octets_envoyes: int = 0
    octets_recus: int = 0
    paquets_envoyes: int = 0
    paquets_recus: int = 0
    ip_virtuelle: str = "—"

    def duree(self) -> str:
        """Retourne la durée de la session au format HH:MM:SS."""
        s = int(time.time() - self.debut)
        return f"{s//3600:02d}:{(s%3600)//60:02d}:{s%60:02d}"

    def debit_moyen(self) -> str:
        """Retourne le débit moyen en KB/s."""
        s = max(1, time.time() - self.debut)
        bps = (self.octets_envoyes + self.octets_recus) / s
        return f"{bps/1024:.1f} KB/s"

    def __str__(self) -> str:
        return (
            f"IP VPN    : {self.ip_virtuelle}\n"
            f"Durée     : {self.duree()}\n"
            f"Envoyés   : {self.octets_envoyes:,} bytes ({self.paquets_envoyes} paquets)\n"
            f"Reçus     : {self.octets_recus:,} bytes ({self.paquets_recus} paquets)\n"
            f"Débit moy.: {self.debit_moyen()}"
        )
