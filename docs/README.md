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

## ⚠️ Limitations éducatives

- **Pas de vrai routage IP** : c'est un tunnel chiffré, pas un VPN complet L3
- **Pas de certificats TLS** : utilise HMAC pré-partagé uniquement
- **Pas de chiffrement de métadonnées** : les longueurs de message sont visibles
- **Pas de PFS** : une clé partagée pour tous les clients

## 🎓 Améliorations futures

- [ ] Transfert de fichiers complets
- [ ] Interface web
- [ ] Implémentation L3 complète (tun/tap)
- [ ] Perfect Forward Secrecy (PFS) avec Diffie-Hellman
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
