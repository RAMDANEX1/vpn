# 🛡️ Guide Complet — Mini VPN Éducatif L2
> Tout ce qu'il faut faire, dans l'ordre, pour avoir une excellente note.

---

## 📊 État actuel du projet

| Fichier | Ce qu'il fait | Problèmes |
|---|---|---|
| `config.py` | IP, port, mot de passe partagé | MDP hardcodé + commité dans Git |
| `crypto.py` | AES-256-GCM chiffrement/déchiffrement | SHA-256 sans sel → dérivation faible |
| `server.py` | Serveur TCP, 1 client à la fois | MDP reçu en clair, pas de threading |
| `client.py` | Client CLI | MDP envoyé en clair sur le réseau |
| `client_gui.py` | Interface Tkinter | Pas de bouton déconnexion, pas de timestamps |
| `test_crypto.py` | 4 tests basiques | Pas de tests serveur/protocole |
| `README.md` | Doc de base | Mentionne `vpn_gui.py` qui n'existe pas |

> ⚠️ **Verdict actuel : c'est un tunnel TCP chiffré, pas encore un VPN.**
> La différence fondamentale : un VPN route de vraies trames IP (couche 3).
> Pour L2, on peut simuler cette couche — mais il faut au minimum un protocole défini.

---

## 🔴 CORRECTIONS CRITIQUES — À faire en premier

### 1. Mot de passe envoyé en clair

**Fichiers :** `server.py`, `client.py`, `client_gui.py`

**Problème :** `conn.recv(4096).decode()` reçoit le mot de passe sans aucun chiffrement.
Un simple `tcpdump` ou Wireshark révèle le mot de passe en clair.

**Solution — Challenge-Response avec HMAC :**

```python
# server.py — dans gerer_client()
import hmac, os

# 1. Serveur envoie un nonce aléatoire
nonce = os.urandom(32)
conn.send(nonce)

# 2. Client répond avec HMAC(nonce, password)
reponse_client = conn.recv(TAILLE_BUFFER)
attendu = hmac.new(MOT_DE_PASSE.encode(), nonce, 'sha256').digest()

if not hmac.compare_digest(reponse_client, attendu):
    conn.send(b"REFUS")
    conn.close()
    return
conn.send(b"OK")
```

```python
# client.py — dans se_connecter()
import hmac

# 1. Recevoir le nonce
nonce = s.recv(32)

# 2. Répondre avec HMAC
reponse = hmac.new(mot_de_passe.encode(), nonce, 'sha256').digest()
s.send(reponse)
```

---

### 2. Dérivation de clé faible (SHA-256 sans sel)

**Fichier :** `crypto.py`

**Problème :** `hashlib.sha256(password)` est vulnérable aux attaques par dictionnaire.
Pas de sel → deux utilisateurs avec le même mot de passe ont la même clé.

**Solution — PBKDF2 avec sel :**

```python
# crypto.py — remplacer _obtenir_cle()
import hashlib, os

SALT_FIXE = b'vpn_educatif_l2_2026'  # sel fixe partagé (ou échangé pendant le handshake)

def _obtenir_cle(mot_de_passe: str, salt: bytes = SALT_FIXE) -> bytes:
    """Dérive une clé AES-256 avec PBKDF2-HMAC-SHA256 (100 000 itérations)."""
    return hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=mot_de_passe.encode('utf-8'),
        salt=salt,
        iterations=100_000,
        dklen=32
    )
```

---

### 3. Mot de passe hardcodé dans Git

**Fichier :** `config.py`, `.gitignore` à créer

**Créer `.gitignore` :**
```
# Environnement virtuel
.venv/
venv/
env/

# Python cache
__pycache__/
*.py[cod]
*.pyo

# Secrets et logs
.env
config_local.py
vpn.log
*.log

# Certificats générés
certs/*.pem
certs/*.key

# IDE
.vscode/
.idea/
```

**Charger le MDP depuis l'environnement :**
```python
# config.py
import os

SERVEUR_IP    = os.getenv("VPN_IP", "127.0.0.1")
SERVEUR_PORT  = int(os.getenv("VPN_PORT", "9999"))
MOT_DE_PASSE  = os.getenv("VPN_PASSWORD", "changez_moi")  # jamais hardcodé
TAILLE_BUFFER = 4096
```

```bash
# Lancer le serveur avec variable d'environnement
VPN_PASSWORD="mon_vrai_mdp" python server.py
```

---

### 4. Serveur mono-client → Multi-client avec threading

**Fichier :** `server.py`

```python
# server.py — version multi-clients
import socket, threading, logging
from config import SERVEUR_IP, SERVEUR_PORT, MOT_DE_PASSE, TAILLE_BUFFER
from crypto import chiffrer, dechiffrer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('vpn.log'),
        logging.StreamHandler()
    ]
)

clients_connectes = {}  # {addr: {"thread": ..., "ip_virtuelle": ...}}
ip_pool = iter([f"10.8.0.{i}" for i in range(2, 255)])
lock = threading.Lock()

def demarrer_serveur():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((SERVEUR_IP, SERVEUR_PORT))
    s.listen(10)
    logging.info(f"Serveur en écoute sur {SERVEUR_IP}:{SERVEUR_PORT}")

    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=gerer_client, args=(conn, addr), daemon=True)
        t.start()
        with lock:
            clients_connectes[addr] = {"thread": t, "ip_virtuelle": next(ip_pool, None)}
        logging.info(f"Client {addr} connecté — {len(clients_connectes)} client(s) actif(s)")
```

---

### 5. Framing TCP — header de longueur

**Fichier :** `protocol.py` (nouveau fichier)

TCP est un flux continu. `recv(4096)` peut recevoir un message partiel
ou deux messages collés. Le framing garantit que chaque message est complet.

```python
# protocol.py — fonctions d'envoi/réception fiables
import struct, socket

def envoyer(sock: socket.socket, data: bytes) -> None:
    """Envoie data précédé de sa longueur sur 4 bytes (big-endian)."""
    header = struct.pack('>I', len(data))
    sock.sendall(header + data)

def recevoir(sock: socket.socket) -> bytes:
    """Reçoit exactement un message complet."""
    # Lire les 4 bytes de longueur
    header = _lire_exactement(sock, 4)
    longueur = struct.unpack('>I', header)[0]
    # Lire exactement longueur bytes
    return _lire_exactement(sock, longueur)

def _lire_exactement(sock: socket.socket, n: int) -> bytes:
    """Lit exactement n bytes depuis le socket."""
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connexion fermée prématurément")
        buf += chunk
    return buf
```

---

### 6. Créer `requirements.txt`

```bash
pip freeze > requirements.txt
```

Contenu minimal :
```
pycryptodome==3.20.0
cryptography==42.0.0
```

---

## 🟠 AMÉLIORATIONS IMPORTANTES

### 7. Protocole avec types de messages

**Nouveau fichier :** `protocol.py`

```python
# protocol.py — types de messages
from enum import IntEnum
import struct

class TypeMessage(IntEnum):
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

# Format d'un paquet : [ type(1) | seq(4) | longueur(4) | payload ]
HEADER_SIZE = 9

def emballer(type_msg: TypeMessage, payload: bytes, seq: int = 0) -> bytes:
    header = struct.pack('>BII', int(type_msg), seq, len(payload))
    return header + payload

def deballer(data: bytes) -> tuple[TypeMessage, int, bytes]:
    type_msg, seq, longueur = struct.unpack('>BII', data[:HEADER_SIZE])
    payload = data[HEADER_SIZE:HEADER_SIZE + longueur]
    return TypeMessage(type_msg), seq, payload
```

---

### 8. Numéros de séquence anti-rejeu

```python
# server.py — dans gerer_client()
seq_attendu = 0
FENETRE_REJEU = 32

def verifier_sequence(seq_recu: int) -> bool:
    global seq_attendu
    if seq_recu < seq_attendu - FENETRE_REJEU:
        logging.warning(f"Paquet rejoué détecté (seq={seq_recu})")
        return False
    seq_attendu = max(seq_attendu, seq_recu + 1)
    return True
```

---

### 9. Heartbeat PING/PONG

```python
# client.py — thread keepalive
import time, threading

def keepalive(sock, mot_de_passe, stop_event):
    while not stop_event.is_set():
        time.sleep(30)
        try:
            from protocol import emballer, TypeMessage
            sock.sendall(emballer(TypeMessage.PING, b'', seq=0))
        except OSError:
            break

stop_event = threading.Event()
t_ping = threading.Thread(target=keepalive, args=(s, mot_de_passe, stop_event), daemon=True)
t_ping.start()
```

---

### 10. Attribution d'IP virtuelle au client

```python
# server.py — dans gerer_client() après AUTH_OK
from itertools import count
compteur_ip = count(2)  # 10.8.0.2, 10.8.0.3, ...

ip_virtuelle = f"10.8.0.{next(compteur_ip)}"
# Envoyer l'IP virtuelle au client dans le message AUTH_OK
conn.sendall(emballer(TypeMessage.AUTH_OK, ip_virtuelle.encode()))
logging.info(f"Client {addr} → IP virtuelle {ip_virtuelle}")
```

---

### 11. Bannissement après échecs répétés

```python
# server.py — anti-bruteforce
from collections import defaultdict
import time

tentatives = defaultdict(lambda: {"count": 0, "ban_until": 0})

def est_banni(ip: str) -> bool:
    info = tentatives[ip]
    if info["ban_until"] > time.time():
        return True
    return False

def enregistrer_echec(ip: str):
    tentatives[ip]["count"] += 1
    if tentatives[ip]["count"] >= 3:
        tentatives[ip]["ban_until"] = time.time() + 60
        logging.warning(f"IP {ip} bannie pour 60s (3 échecs)")
```

---

### 12. Compression avant chiffrement

```python
# crypto.py — ajouter compression optionnelle
import zlib

def chiffrer(message: str, mot_de_passe: str, compresser: bool = True) -> bytes:
    cle = _obtenir_cle(mot_de_passe)
    iv  = os.urandom(12)
    
    payload = message.encode('utf-8')
    flag_compression = b'\x01' if compresser else b'\x00'
    if compresser:
        payload_compresse = zlib.compress(payload)
        if len(payload_compresse) < len(payload):  # compression utile ?
            payload = payload_compresse
        else:
            flag_compression = b'\x00'
    
    cipher = AES.new(cle, AES.MODE_GCM, nonce=iv)
    chiffre, tag = cipher.encrypt_and_digest(payload)
    return flag_compression + iv + chiffre + tag

def dechiffrer(donnees: bytes, mot_de_passe: str) -> str:
    flag_compression = donnees[0:1]
    cle    = _obtenir_cle(mot_de_passe)
    iv     = donnees[1:13]
    chiffre = donnees[13:-16]
    tag    = donnees[-16:]
    cipher = AES.new(cle, AES.MODE_GCM, nonce=iv)
    payload = cipher.decrypt_and_verify(chiffre, tag)
    if flag_compression == b'\x01':
        payload = zlib.decompress(payload)
    return payload.decode('utf-8')
```

---

### 13. Transfert de fichiers

```python
# client.py — commande /send
import os

def envoyer_fichier(sock, chemin: str, mot_de_passe: str):
    nom = os.path.basename(chemin)
    taille = os.path.getsize(chemin)
    CHUNK = 4096
    
    # Annoncer le fichier
    meta = f"{nom}:{taille}".encode()
    sock.sendall(emballer(TypeMessage.FILE_START, chiffrer_bytes(meta, mot_de_passe)))
    
    # Envoyer en morceaux
    with open(chemin, 'rb') as f:
        envoyé = 0
        while chunk := f.read(CHUNK):
            sock.sendall(emballer(TypeMessage.FILE_CHUNK, chiffrer_bytes(chunk, mot_de_passe)))
            envoyé += len(chunk)
            print(f"\r[FICHIER] {envoyé}/{taille} bytes ({100*envoyé//taille}%)", end='')
    
    sock.sendall(emballer(TypeMessage.FILE_END, b''))
    print(f"\n[FICHIER] '{nom}' envoyé ({taille} bytes)")
```

---

### 14. Statistiques de session

```python
# stats.py — nouveau fichier
import time
from dataclasses import dataclass, field

@dataclass
class SessionStats:
    debut: float = field(default_factory=time.time)
    octets_envoyes: int = 0
    octets_recus: int = 0
    paquets_envoyes: int = 0
    paquets_recus: int = 0
    ip_virtuelle: str = "—"

    def duree(self) -> str:
        s = int(time.time() - self.debut)
        return f"{s//3600:02d}:{(s%3600)//60:02d}:{s%60:02d}"

    def debit_moyen(self) -> str:
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
```

---

### 15. Argument CLI avec argparse

```python
# server.py — arguments en ligne de commande
import argparse

def parse_args():
    p = argparse.ArgumentParser(description="Serveur VPN éducatif")
    p.add_argument('--host', default='127.0.0.1', help='IP d\'écoute')
    p.add_argument('--port', type=int, default=9999, help='Port TCP')
    p.add_argument('--max-clients', type=int, default=10, help='Max clients simultanés')
    p.add_argument('--log-level', default='INFO', choices=['DEBUG','INFO','WARNING'])
    return p.parse_args()

# Utilisation : python server.py --port 8888 --max-clients 5
```

---

### 16. Exceptions personnalisées

**Nouveau fichier :** `exceptions.py`

```python
# exceptions.py
class VPNException(Exception):
    """Exception de base du protocole VPN."""

class AuthenticationError(VPNException):
    """Échec d'authentification."""

class PacketError(VPNException):
    """Paquet mal formé ou corrompu."""

class TunnelError(VPNException):
    """Erreur sur le tunnel chiffré."""

class ReplayAttackError(VPNException):
    """Paquet rejoué détecté."""
```

---

### 17. Améliorer le GUI — bouton déconnexion + timestamps + onglets

```python
# client_gui.py — améliorations

# 1. Bouton déconnexion (à ajouter dans __init__)
self.disconnect_button = tk.Button(conn_frame, text="Déconnecter",
                                    command=self.disconnect, state='disabled')
self.disconnect_button.grid(row=3, column=1, pady=5)

# Activer à la connexion
self.connect_button.config(state='disabled')
self.disconnect_button.config(state='normal')

# 2. Timestamps dans les messages
from datetime import datetime
def log_message(self, message, sender="Système"):
    heure = datetime.now().strftime("%H:%M:%S")
    self.history_text.config(state='normal')
    self.history_text.insert(tk.END, f"[{heure}] [{sender}] {message}\n")
    self.history_text.config(state='disabled')
    self.history_text.see(tk.END)

# 3. Onglets avec ttk.Notebook
from tkinter import ttk
notebook = ttk.Notebook(master)
tab_chat  = tk.Frame(notebook)
tab_stats = tk.Frame(notebook)
tab_logs  = tk.Frame(notebook)
notebook.add(tab_chat,  text='Chat')
notebook.add(tab_stats, text='Statistiques')
notebook.add(tab_logs,  text='Logs')
notebook.pack(fill=tk.BOTH, expand=True)
```

---

### 18. Amélioration test_crypto.py → unittest propre

```python
# tests/test_crypto.py
import unittest
from crypto import chiffrer, dechiffrer

class TestCrypto(unittest.TestCase):
    MDP = "vpn_test_2026"

    def test_roundtrip(self):
        msg = "Bonjour, monde !"
        self.assertEqual(dechiffrer(chiffrer(msg, self.MDP), self.MDP), msg)

    def test_iv_aleatoire(self):
        b1 = chiffrer("même message", self.MDP)
        b2 = chiffrer("même message", self.MDP)
        self.assertNotEqual(b1, b2, "IV doit être aléatoire")

    def test_mauvais_mdp(self):
        with self.assertRaises(ValueError):
            dechiffrer(chiffrer("secret", self.MDP), "mauvais")

    def test_paquet_corrompu(self):
        paquet = bytearray(chiffrer("secret", self.MDP))
        paquet[15] ^= 0xFF
        with self.assertRaises(ValueError):
            dechiffrer(bytes(paquet), self.MDP)

    def test_message_vide(self):
        msg = ""
        self.assertEqual(dechiffrer(chiffrer(msg, self.MDP), self.MDP), msg)

    def test_message_long(self):
        msg = "A" * 10_000
        self.assertEqual(dechiffrer(chiffrer(msg, self.MDP), self.MDP), msg)

    def test_unicode(self):
        msg = "日本語テスト 🔒"
        self.assertEqual(dechiffrer(chiffrer(msg, self.MDP), self.MDP), msg)

if __name__ == '__main__':
    unittest.main()
```

---

## 📁 Structure finale du projet

```
mini-vpn/
├── src/
│   ├── config.py          ← IP, port (MDP depuis .env)
│   ├── crypto.py          ← AES-256-GCM + PBKDF2 + compression
│   ├── protocol.py        ← Types de messages + framing TCP
│   ├── exceptions.py      ← Hiérarchie d'exceptions
│   ├── stats.py           ← Métriques de session
│   ├── server.py          ← Serveur multi-clients + logging
│   ├── client.py          ← Client CLI + keepalive
│   └── client_gui.py      ← GUI Tkinter avec onglets
│
├── tests/
│   ├── test_crypto.py     ← Tests unitaires crypto (unittest)
│   ├── test_protocol.py   ← Tests protocole avec mock
│   └── test_integration.py← Test serveur+client bout en bout
│
├── certs/                 ← Certificats RSA auto-signés (gitignore)
├── docs/
│   ├── architecture.md    ← Schéma du protocole
│   └── rapport.docx       ← Rapport de projet
│
├── .env.example           ← Template (pas le vrai .env !)
├── .gitignore
├── requirements.txt
└── README.md
```

---

## 🎬 DEMO — Comment présenter le projet

### Étape 1 — Préparer Wireshark

Wireshark permet de **prouver visuellement** que les données sont chiffrées.

```bash
# Installer Wireshark sur Ubuntu/Debian
sudo apt install wireshark

# Sur Windows : télécharger sur wireshark.org
```

**Configuration du filtre Wireshark :**
```
tcp.port == 9999
```

**Ce que vous allez montrer :**

1. Lancer Wireshark sur l'interface `lo` (loopback) ou `localhost`
2. Démarrer la capture
3. Lancer le serveur et le client
4. Envoyer un message depuis le client
5. Dans Wireshark → clic droit sur un paquet → *Follow TCP Stream*

**Sans chiffrement :** le texte apparaît en clair dans le stream.
**Avec votre VPN :** le stream affiche des bytes illisibles (`ÎÔ∂√©…`).

> 💡 **Astuce démo :** préparer deux captures Wireshark à l'avance (une "sans VPN" avec un netcat, une "avec VPN") pour montrer la différence en 30 secondes.

---

### Étape 2 — Lancer la démo complète (ordre exact)

```bash
# Terminal 1 — Lancer Wireshark d'abord
wireshark -i lo -k -f "tcp port 9999" &

# Terminal 2 — Serveur
cd mini-vpn/src
VPN_PASSWORD="demo2026" python server.py --port 9999

# Terminal 3 — Client
cd mini-vpn/src
VPN_PASSWORD="demo2026" python client.py --host 127.0.0.1 --port 9999

# Ou GUI :
python client_gui.py
```

---

### Étape 3 — Script de démo pour la soutenance (5 minutes)

| Minute | Action | Ce qu'on explique |
|---|---|---|
| 0:00 | Lancer serveur + Wireshark | "Le serveur écoute sur le port 9999, Wireshark capture tout" |
| 0:30 | Connecter le client avec bon MDP | "Handshake : nonce → HMAC → IP virtuelle 10.8.0.2 attribuée" |
| 1:00 | Envoyer "Bonjour" | Montrer Wireshark : stream illisible |
| 1:30 | Tentative connexion mauvais MDP | "Bannissement après 3 échecs" |
| 2:00 | Ouvrir 2 clients simultanément | "Multi-client : threading, chaque session est isolée" |
| 2:30 | Envoyer un fichier `/send test.txt` | "Transfert de fichiers chiffrés en chunks" |
| 3:00 | Afficher stats | "238 bytes envoyés, débit 4.2 KB/s, durée 02:47" |
| 3:30 | Mode split clair/chiffré GUI | "Même texte → totalement illisible sur le réseau" |
| 4:00 | Lancer les tests | `python -m pytest tests/ -v` → tous verts |
| 4:30 | Montrer le code `protocol.py` | "Notre protocole maison : HELLO, AUTH, DATA, PING, CLOSE" |

---

### Commandes Wireshark utiles pour la démo

```
# Filtre de base
tcp.port == 9999

# Voir uniquement les paquets DATA (payload > 28 bytes = IV+tag minimum)
tcp.port == 9999 && tcp.len > 28

# Exclure les keepalives TCP
tcp.port == 9999 && tcp.len > 0

# Coulorer les paquets client→serveur en bleu, serveur→client en vert
# (dans Wireshark : View > Coloring Rules)
```

**Ce qu'on voit sans chiffrement (netcat pour comparaison) :**
```
00000000  42 6f 6e 6a 6f 75 72 20  6c 65 20 6d 6f 6e 64 65   Bonjour  le monde
```

**Ce qu'on voit avec votre VPN :**
```
00000000  00 d4 f3 a1 9c 2e 7b 4f  88 12 c5 3a 91 e7 02 b6   .ÔóĦ.{O ĸ.Å:ĺç.¶
00000010  5c 3d 8f 2a 17 dd 4e f0  cc 81 a3 7e b9 05 44 19   \=ï*.ÝNð Ì.£~¹.D.
```

> 🎯 C'est ce contraste que vous devez montrer. C'est la preuve que votre VPN fonctionne.

---

### Questions fréquentes en soutenance (et réponses)

**"Pourquoi AES-GCM et pas AES-CBC ?"**
> GCM est un mode AEAD (Authenticated Encryption with Associated Data). Il chiffre ET authentifie en une seule passe. CBC ne protège pas contre la modification du ciphertext. GCM est le standard TLS 1.3.

**"C'est quoi la différence avec HTTPS ?"**
> HTTPS protège une connexion HTTP (couche application). Un VPN protège tout le trafic IP (couche réseau), y compris DNS, UDP, et tous les ports. Notre projet simule cette couche réseau avec les IP virtuelles 10.8.0.x.

**"Pourquoi SHA-256 ne suffit pas pour dériver la clé ?"**
> SHA-256 est rapide (milliards d'opérations/seconde sur GPU). PBKDF2 avec 100 000 itérations rend une attaque bruteforce 100 000× plus lente. Sur un GPU RTX 4090 : SHA-256 → 20 milliards/s, PBKDF2 → 200 000/s.

**"Comment votre VPN compare-t-il à WireGuard ?"**
> WireGuard utilise ChaCha20-Poly1305, Curve25519 pour le DH, et des interfaces TUN réelles. Notre implémentation utilise AES-256-GCM et simule la couche réseau. L'objectif pédagogique est le même : comprendre les briques cryptographiques.

**"Qu'est-ce qui manquerait pour un vrai VPN de production ?"**
> Interface TUN/TAP réelle, PKI complète (CA, certificats signés), rotation automatique des clés, protection contre les attaques DDoS, support IPv6. Mais les principes cryptographiques sont identiques.

---

## ✅ CHECKLIST FINALE — Avant de rendre

### Sécurité
- [ ] Mot de passe envoyé via HMAC-challenge (pas en clair)
- [ ] Dérivation de clé PBKDF2 (pas SHA-256 seul)
- [ ] Mot de passe chargé depuis variable d'environnement
- [ ] `.gitignore` en place (`.venv`, `__pycache__`, `.env`)
- [ ] Anti-bruteforce (ban IP après 3 échecs)
- [ ] Timeout d'authentification (5 secondes)

### Architecture
- [ ] Serveur multi-clients (threading)
- [ ] Framing TCP (header de longueur 4 bytes)
- [ ] `protocol.py` avec types de messages (enum)
- [ ] Numéros de séquence anti-rejeu
- [ ] Heartbeat PING/PONG (toutes les 30s)
- [ ] Attribution d'IP virtuelle au client

### Fonctionnalités
- [ ] Transfert de fichiers chiffrés
- [ ] Statistiques de session (bytes, durée, débit)
- [ ] Reconnexion automatique (3 tentatives)
- [ ] Compression avant chiffrement (zlib)
- [ ] Arguments CLI (argparse)
- [ ] Logging dans fichier `vpn.log`

### GUI
- [ ] Bouton "Déconnecter" fonctionnel
- [ ] Timestamps sur chaque message
- [ ] Onglets : Chat / Stats / Logs
- [ ] Mode split clair vs bytes chiffrés (hex)
- [ ] GUI serveur avec liste des clients connectés

### Qualité du code
- [ ] `requirements.txt` à jour
- [ ] `exceptions.py` avec hiérarchie propre
- [ ] Type hints sur toutes les fonctions
- [ ] Docstrings sur toutes les classes/méthodes
- [ ] Tests unittest (minimum 10 tests)
- [ ] Structure de dossiers propre (`src/`, `tests/`, `docs/`)

### Documentation
- [ ] `README.md` corrigé (plus de `vpn_gui.py`)
- [ ] Schéma du protocole dans `docs/`
- [ ] Format du paquet documenté `[ IV | cipher | tag ]`
- [ ] Section "Limites et pistes d'amélioration" dans le rapport

---

## 🏆 VERDICT FINAL — Est-ce un excellent projet ?

### Avec uniquement les corrections critiques (1 à 6)
> **Note estimée : 12-14/20**
> Le projet est fonctionnel et sécurisé au niveau basique.
> C'est encore un "chat chiffré", pas un VPN.

### Avec les corrections + améliorations importantes (1 à 18)
> **Note estimée : 15-17/20**
> Protocole défini, multi-client, framing TCP, IP virtuelle, stats.
> C'est un **vrai tunnel VPN** avec une architecture solide.
> La démo Wireshark emporte le jury.

### Avec tout + TUN/TAP réel + DH + certificats RSA
> **Note estimée : 18-20/20**
> Niveau qui dépasse le cursus L2 standard.
> Équivalent à une implémentation pédagogique d'OpenVPN.
> Présenter dans cet ordre : démo Wireshark → protocole → code crypto → tests.

### Ce qui fait vraiment la différence devant un jury
1. **La démo Wireshark** — voir les bytes illisibles en live = 2 points garantis
2. **Le protocole avec types de messages** — montre la compréhension réseau
3. **Les tests qui passent** — `pytest tests/ -v` tout vert = sérieux immédiat
4. **Savoir répondre aux questions** — les réponses préparées ci-dessus

> 🎯 **Conseil :** ne cherchez pas à tout implémenter.
> Faites les 6 corrections critiques + le protocole + la démo Wireshark.
> C'est 80% de la valeur du projet pour 30% de l'effort.
