# 🔒 Mini VPN Sécurisé — Projet Éducatif

Un tunnel VPN chiffré et multi-client développé en Python, démontrant les principes essentiels de la sécurité réseau et du chiffrement.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-success)

---

## ✨ Fonctionnalités de Sécurité

| Fonctionnalité | Détail |
|---|---|
| 🔐 **Chiffrement** | AES-256-GCM (authentifié) |
| 🔑 **Dérivation clé** | PBKDF2 avec 100 000 itérations HMAC-SHA256 |
| ✅ **Authentification** | Challenge-Response HMAC (mot de passe jamais en clair) |
| 📦 **Framing TCP** | Headers de longueur pour éviter la fragmentation |
| 🛡️ **Anti-bruteforce** | Bannissement après 3 échecs d'authentification (60s) |
| 🤝 **Multi-client** | Threading pour gérer plusieurs connexions simultanées |
| 📊 **Compression** | zlib optionnelle avant chiffrement |
| 💓 **Keepalive** | PING/PONG automatique pour maintenir les connexions |
| 📝 **Logging** | Journal complet dans `vpn.log` |

---

## 📋 Installation

### Prérequis
- Python 3.8+
- pip

### Étapes

```bash
# Cloner le repository
git clone https://github.com/RAMDANEX1/vpn.git
cd vpn

# Installer les dépendances
pip install -r requirements.txt

# (Optionnel) Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

### Dépendances

- `pycryptodome` : Chiffrement AES-256-GCM
- `cryptography` : Dérivation PBKDF2
- `tkinter` : Interface graphique (généralement inclus avec Python)

---

## 🚀 Démarrage Rapide

### 1️⃣ Lancer le Serveur VPN

```bash
# Terminal 1
VPN_PASSWORD="mon_mot_de_passe_secret" python servers/server.py

# Options disponibles
python servers/server.py --help

# Exemple avec port custom et 20 clients max
VPN_PASSWORD="secret123" python servers/server.py --port 8888 --max-clients 20 --log-level DEBUG
```

### 2️⃣ Lancer le Client

**Option A : Interface Graphique (Recommandée)**
```bash
# Terminal 2
python servers/client_gui.py
```

**Option B : Ligne de commande**
```bash
# Terminal 2
python servers/client.py
```

---

## 🧪 Tests

Vérifiez l'intégrité du chiffrement :

```bash
# Tests cryptographiques
python tests/test_crypto.py

# Tests de transfert de fichiers
python tests/test_file_transfer.py
```

**Ce que les tests vérifient :**
- ✓ Roundtrip chiffrement/déchiffrement
- ✓ IV aléatoire (pas de déterminisme)
- ✓ Rejet des mots de passe incorrects
- ✓ Détection des paquets corrompus
- ✓ Compression zlib
- ✓ Support Unicode/Emojis
- ✓ Dérivation PBKDF2 correcte

---

## 📁 Structure du Projet

```
vpn/
├── 📄 README.md                 ← Vous êtes ici
├── 📄 requirements.txt          ← Dépendances Python
├── 📄 .env.example              ← Configuration exemple
│
├── 📂 core/                     ← Modules de sécurité
│   ├── config.py                ← Configuration centralisée
│   ├── crypto.py                ← Chiffrement AES-256-GCM + PBKDF2
│   ├── protocol.py              ← Framing TCP + types de messages
│   ├── exceptions.py            ← Exceptions personnalisées
│   └── __init__.py
│
├── 📂 servers/                  ← Serveur et clients
│   ├── server.py                ← Serveur multi-client
│   ├── client.py                ← Client CLI
│   ├── client_gui.py            ← Interface GUI (Tkinter)
│   └── file_transfer.py         ← Transfert sécurisé de fichiers
│
├── 📂 tests/                    ← Suite de tests
│   ├── test_crypto.py           ← Tests de chiffrement
│   ├── test_file_transfer.py    ← Tests de transfert
│   └── test_input.txt           ← Données de test
│
├── 📂 tools/                    ← Utilitaires
│   ├── run_server.py
│   └── run_gui.py
│
├── 📂 docs/                     ← Documentation
│   ├── README.md                ← Documentation détaillée
│   └── DEMO_SCRIPT.md           ← Script de démonstration
│
├── run_server.bat / .sh         ← Scripts de lancement Windows/Unix
└── run_gui.bat / .sh            ← Scripts de lancement GUI
```

---

## 🔐 Protocole de Sécurité

### Authentification (Challenge-Response HMAC)

```
Client                                  Serveur
  |                                       |
  |---- 1. Envoie hash(password) ------->|
  |                                       |
  |<---- 2. Challenge HMAC aléatoire ----|
  |                                       |
  |---- 3. Response = HMAC(Challenge) -->|
  |                                       |
  |<---- ✅ Authentification réussie ----|
```

### Chiffrement des Messages

```
Message "Hello VPN"
    ↓
Compression zlib (optionnel)
    ↓
Chiffrement AES-256-GCM
    ↓
[Longueur (4 bytes) + Données chiffrées]
    ↓
Envoi TCP au serveur
```

---

## 📊 Exemple d'Utilisation

### Serveur
```bash
$ VPN_PASSWORD="secure123" python servers/server.py --port 5000
[INFO] Serveur VPN démarré sur 127.0.0.1:5000
[INFO] En attente de connexions...
[INFO] ✅ Client 192.168.1.100:54321 authentifié (Alice)
[INFO] 📨 Message reçu: "Hello Server"
[INFO] 💾 Transfert de fichier: backup.zip (2.5 MB)
```

### Client GUI
```
┌─────────────────────────────────┐
│  Mini VPN - Client              │
├─────────────────────────────────┤
│ IP Serveur: 127.0.0.1          │
│ Port: 5000                      │
│ Mot de passe: ••••••••          │
│ [Connecter]                     │
├─────────────────────────────────┤
│ [14:23:45] Connecté au serveur  │
│ [14:23:46] Authentification OK  │
│ [14:23:50] Message envoyé       │
├─────────────────────────────────┤
│ Message: [_______________]      │
│          [Envoyer]              │
└─────────────────────────────────┘
```

---

## 🎓 Concepts Pédagogiques

Ce projet illustre :

- **Chiffrement symétrique** : AES avec Galois/Counter Mode (GCM)
- **Dérivation de clé** : PBKDF2 pour transformer un mot de passe en clé robuste
- **Authentification** : Challenge-Response HMAC
- **Intégrité** : Tags d'authentification GCM
- **Programmation réseau** : Sockets TCP, threading, framing
- **Gestion d'erreurs** : Anti-bruteforce, timeouts, validations

---

## 📜 Configuration

Créez un fichier `.env` basé sur `.env.example` :

```bash
cp .env.example .env
```

Éditez `.env` :
```
VPN_IP=127.0.0.1
VPN_PORT=5000
VPN_PASSWORD=your_secure_password
LOG_LEVEL=INFO
```

---

## 🐛 Dépannage

| Problème | Solution |
|---|---|
| `Connection refused` | Vérifier que le serveur est lancé et écoute le bon port |
| `Authentication failed` | Vérifier que le mot de passe est identique côté client et serveur |
| `ModuleNotFoundError: No module named 'Crypto'` | Installer les dépendances : `pip install -r requirements.txt` |
| `Address already in use` | Utiliser un port différent : `python server.py --port 8888` |

---

## 📝 Logs

Les événements sont enregistrés dans `vpn.log` :

```
[2026-05-08 14:23:45] [INFO] Serveur démarré sur 127.0.0.1:5000
[2026-05-08 14:23:50] [INFO] Connexion reçue: 192.168.1.100:54321
[2026-05-08 14:23:51] [INFO] Authentification réussie
[2026-05-08 14:23:55] [DEBUG] Message reçu (256 bytes)
```

---

## 📄 Licence

Projet éducatif open-source. MIT License - Libre d'utilisation.

---

## 👨‍💻 Auteur

Développé comme démonstration des principes de sécurité réseau.par :
**ramdane**
**rayane**
**dhayae**
**mohammed**

---

## 🚀 Améliorations Futures

- [ ] Support TLS/SSL pour handshake initial
- [ ] Certificats X.509 pour authentification forte
- [ ] Interface web (Django/FastAPI)
- [ ] Transfert sécurisé de fichiers (déjà partiellement implémenté)
- [ ] Statistiques de bande passante
- [ ] Documentation API complète

---

## 📞 Support

Pour des questions ou signaler des bugs, ouvrez une **Issue** sur GitHub.

---

**⭐ Si ce projet vous a été utile, n'hésitez pas à le marquer avec une étoile !**
