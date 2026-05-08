                                                                                                                                                                                                                                                                                                                                                    # Mini VPN Éducatif — Version Sécurisée L2

Simulation d'un tunnel VPN chiffré en Python avec authentification HMAC, compression optionnelle, et multi-client.

## 🔒 Fonctionnalités de sécurité

- ✅ **Chiffrement AES-256-GCM** : chiffrement authentifié
- ✅ **Dérivation clé PBKDF2** : 100 000 itérations HMAC-SHA256 + sel
- ✅ **Authentification Challenge-Response HMAC** : mot de passe jamais en clair
- ✅ **Framing TCP** : header de longueur pour éviter les paquets fragmentés
- ✅ **Types de messages** : protocole robuste avec numérotation
- ✅ **Compression optionnelle** : zlib avant chiffrement
- ✅ **Anti-bruteforce** : bannissement après 3 échecs (60s)
- ✅ **Multi-client** : threading pour gérer plusieurs connexions simultanées
- ✅ **Logging** : journal des événements dans `vpn.log`
- ✅ **Keepalive PING/PONG** : maintien de la connexion

## 📋 Installation

```bash
# Installer les dépendances
pip install -r requirements.txt

# Ou manuellement
pip install pycryptodome cryptography
```

## 🚀 Lancer le projet

### Serveur VPN

**Terminal 1 :**
```bash
# Avec le mot de passe depuis l'environnement
VPN_PASSWORD="mon_mot_de_passe_secret" python server.py

# Options disponibles
python server.py --help

# Exemple avec custom port et 20 clients max
VPN_PASSWORD="secret123" python server.py --port 8888 --max-clients 20 --log-level DEBUG
```

### Client CLI

**Terminal 2 :**
```bash
python client.py
# Il demandera le mot de passe interactivement
```

### Interface graphique (GUI)

```bash
python client_gui.py
```

Fonctionnalités :
- Configuration de l'IP/port du serveur
- Authentification sécurisée
- Affichage des messages avec **timestamps**
- **Bouton de déconnexion** explicite
- Keepalive automatique

## 🧪 Tests

### Tests cryptographiques

```bash
python test_crypto.py
```

Vérifie :
- ✓ Roundtrip chiffrement/déchiffrement
- ✓ IV aléatoire (pas de déterminisme)
- ✓ Rejet des mots de passe incorrects
- ✓ Détection des paquets corrompus
- ✓ Compression zlib
- ✓ Support Unicode/Emojis
- ✓ Dérivation PBKDF2

## 📂 Structure du projet

```
vpn/
├── config.py              ← Configuration (IP, port, MDP via env)
├── crypto.py              ← AES-256-GCM + PBKDF2 + compression
├── protocol.py            ← Framing TCP + types de messages
├── exceptions.py          ← Exceptions personnalisées
├── stats.py               ← Statistiques de session
├── file_transfer.py       ← Transfert sécurisé de fichiers
│
├── server.py              ← Serveur multi-client avec HMAC auth
├── client.py              ← Client CLI avec HMAC auth + keepalive
├── client_gui.py          ← GUI Tkinter avec timestamps
│
├── test_crypto.py         ← Tests unitaires complets
├── requirements.txt       ← Dépendances Python
├── .gitignore             ← Secrets et fichiers temporaires
│
├── README.md              ← Ce fichier
└── vpn.log                ← Logs du serveur (généré)
```

## 🔐 Protocole de sécurité

### Phase 1 : Authentification (Challenge-Response)

1. **Client → Serveur** : Connexion TCP
2. **Serveur → Client** : Envoi d'un **nonce aléatoire** (32 bytes) de type `CHALLENGE`
3. **Client → Serveur** : Calcul et envoi `HMAC-SHA256(nonce, password)` de type `AUTH_REQ`
4. **Serveur** : Vérifie le HMAC avec `hmac.compare_digest()` (timing-safe)
5. **Serveur → Client** : Réponse `AUTH_OK` ou `AUTH_FAIL`

### Phase 2 : Chiffrement des messages

Chaque message est emballé selon :
```
[type(1) | seq(4) | longueur(4) | payload_chiffré]

payload_chiffré = [flag_compression(1) | IV(12) | AES-256-GCM(data) | tag(16)]
```

Types de messages :
- `0x01` : HELLO
- `0x02` : CHALLENGE (auth)
- `0x03` : AUTH_REQ (auth response)
- `0x04` : AUTH_OK
- `0x05` : AUTH_FAIL
- `0x10` : DATA (messages chiffrés)
- `0x20` : PING (keepalive)
- `0x21` : PONG (keepalive response)
- `0xFF` : CLOSE (déconnexion)

## 🛡️ Variables d'environnement

```bash
VPN_IP       # IP d'écoute du serveur (défaut: 127.0.0.1)
VPN_PORT     # Port TCP (défaut: 9999)
VPN_PASSWORD # Mot de passe partagé (REQUIS pour la sécurité)
```

Exemple d'utilisation :
```bash
export VPN_PASSWORD="kabyle2026_ultra_secret"
export VPN_PORT=8888
python server.py --max-clients 50
```

## 📊 Statistiques de session

Le serveur enregistre pour chaque client :
- **IP virtuelle** : 10.8.0.2, 10.8.0.3, ...
- **Octets envoyés/reçus**
- **Nombre de paquets**
- **Débit moyen**
- **Durée de connexion**

## 🔬 Analyse avec Wireshark

### Installation

```bash
# Windows / Mac / Linux
# Télécharger depuis : https://www.wireshark.org/download/

# Linux (Debian/Kali)
sudo apt install wireshark
```

### Capturer le trafic

**Terminal 1 - Serveur :**
```bash
export VPN_PASSWORD="test123"
python servers/server.py --host 127.0.0.1 --port 5000
```

**Terminal 2 - Wireshark :**
```bash
# Lancer Wireshark avec admin/sudo
sudo wireshark

# OU en CLI (plus rapide)
sudo tcpdump -i lo -n port 5000 -w vpn_capture.pcap
```

**Terminal 3 - Client :**
```bash
python servers/client.py
# Entrer IP: 127.0.0.1
# Entrer port: 5000
# Entrer mot de passe: test123
# Envoyer quelques messages
```

### Analyser dans Wireshark

1. Ouvrir le fichier capturé ou voir live
2. Filtrer : `tcp.port == 5000`
3. Observer les paquets :
   - **Paquets 1-2** : Handshake TCP
   - **Paquet 3** : `CHALLENGE` (type 0x02) - nonce 32 bytes en clair
   - **Paquet 4** : `AUTH_REQ` (type 0x03) - HMAC chiffré
   - **Paquet 5+** : `DATA` (type 0x10) - Payload complètement chiffré ✅

### Observations clés

```
Frame 1: TCP SYN → Établissement connexion
Frame 2: TCP ACK
Frame 3: [0x02 | seq | len | nonce_aléatoire(32)]  ← CHALLENGE EN CLAIR
Frame 4: [0x03 | seq | len | chiffré(HMAC)]        ← AUTH RESPONSE (déchiffrable avec pcap-ng + clé)
Frame 5: [0x10 | seq | len | AES-256-GCM(data)]    ← DATA CHIFFRÉ ✅ (opaque)
Frame 6: [0x20 | seq | len | PING chiffré]         ← KEEPALIVE (opaque)
```

**✅ Observations de sécurité :**
- Nonce unique par connexion (Frame 3) ✓
- Payload des données complètement chiffré (Frames 5+) ✓
- Longueur des messages visible (possible fingerprinting) ⚠️
- Pas de chiffrement de métadonnées (type visible) ⚠️

### Exportation des paquets

**Extraire les données brutes :**
```bash
# Depuis la capture .pcap
tcpdump -r vpn_capture.pcap -A -X port 5000 | head -50

# Analyser les longueurs
tcpdump -r vpn_capture.pcap -n 'port 5000' | awk '{print $NF}' | sort | uniq -c
```

## 🔑 Diffie-Hellman Key Exchange (Clés uniques par session)

**Problème résolu :** Le sel PBKDF2 était fixe (même sel = même clé pour tous les clients)

**Solution implémentée :** Diffie-Hellman (RFC 3526 - 2048-bit MODP Group 14)

```python
# Avant (❌ FAILLE)
SALT_FIXE = b'vpn_educatif_l2_2026'  # Tous les clients → même clé !

# Après (✅ FIXÉ)
DH_P = 0xFFFF...FFFF  # 2048-bit prime
DH_G = 2              # générateur

# Chaque session :
server_private, server_public = dh_generate_key()
client_private, client_public = dh_generate_key()

# Échange des clés publiques
server_salt = dh_compute_shared_secret(server_private, client_public)
client_salt = dh_compute_shared_secret(client_private, server_public)

# Salt unique par session ! (même pour les deux)
assert server_salt == client_salt  ✓
```

**Test de vérification :**
```bash
python test_dh.py
# [OK] Secrets match: True
# [OK] Session keys match: True
# Each session gets unique key
```

**Résultat :** Chaque session client-serveur obtient une clé AES-256 **unique**, même avec le même mot de passe.

## ⚠️ Limitations éducatives

- **Pas de vrai routage IP** : c'est un tunnel chiffré, pas un VPN complet L3
- **Pas de certificats TLS** : utilise HMAC pré-partagé uniquement
- **Pas de chiffrement de métadonnées** : les longueurs de message sont visibles
- ~~**Pas de PFS** : une clé partagée pour tous les clients~~ **FIXÉ** : DH fournit now session-unique keys

## 🎓 Améliorations futures

- [ ] Intégrer DH handshake dans server.py/client.py
- [ ] Transfert de fichiers complets
- [ ] Interface web
- [ ] Implémentation L3 complète (tun/tap)
- [ ] Rate limiting côté serveur
- [ ] Session timeouts
- [ ] Audit trail complet

## 👥 Équipe

- **M1** : Chef projet + rapport
- **M2** : Cryptographie (crypto.py, test_crypto.py)
- **M3** : Serveur (server.py)
- **M4** : Client + tests (client.py, client_gui.py)

## 📖 Références

- NIST SP 800-132 : PBKDF2
- FIPS 197 : AES
- RFC 5116 : AEAD Interface and Algorithms
- RFC 2104 : HMAC
