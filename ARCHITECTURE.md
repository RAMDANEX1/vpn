# 📂 Architecture Finale — VPN Éducatif

## Structure du Projet

```
vpn/
├── 🔐 core/                    # Modules de base (cryptographie & protocole)
│   ├── __init__.py
│   ├── crypto.py              # AES-256-GCM, PBKDF2-HMAC-SHA256, zlib
│   ├── protocol.py            # Framing TCP, message types enum
│   ├── exceptions.py          # Hiérarchie d'exceptions personnalisées
│   └── config.py              # Configuration centralisée (env vars)
│
├── 🖥️ servers/                # Serveur & clients VPN
│   ├── __init__.py
│   ├── server.py              # Multi-client, auth HMAC, anti-bruteforce
│   ├── client.py              # Client CLI simple
│   ├── client_gui.py          # Client GUI professionnel (Tkinter)
│   └── file_transfer.py       # Transfert sécurisé de fichiers
│
├── 🛠️ tools/                  # Outils et launchers
│   ├── __init__.py
│   ├── run_server.py          # Launcher interactif serveur
│   ├── run_gui.py             # Launcher client GUI
│   └── test_password_sync.py  # Diagnostic de config
│
├── ✅ tests/                  # Suite de tests
│   ├── __init__.py
│   ├── test_crypto.py         # Tests unitaires crypto
│   ├── test_complete.py       # Tests d'intégration
│   ├── test_file_transfer.py  # Tests transfert fichiers
│   └── test_input.txt         # Données de test
│
├── 📚 docs/                   # Documentation
│   ├── __init__.py
│   ├── README.md              # Guide principal
│   ├── QUICKSTART.md          # Démarrage rapide (3 étapes)
│   ├── DEMO_SCRIPT.md         # Scénario de démo complet
│   └── GUIDE_FILE_TRANSFER.md # Guide transfert fichiers
│
├── 🚀 Launchers racine        # Scripts de lancement (choix 1)
│   ├── run_server.bat         # Lancer serveur (Windows)
│   ├── run_server.sh          # Lancer serveur (Linux/Mac)
│   ├── run_gui.bat            # Lancer GUI (Windows)
│   └── run_gui.sh             # Lancer GUI (Linux/Mac)
│
├── 📦 requirements.txt        # Dépendances Python
├── .env.example               # Modèle de variables d'env
├── .gitignore                 # Fichiers ignorés par Git
└── .git/                      # Historique Git

```

---

## 🚀 Lancement Rapide

### Windows (Recommandé — Double-clic)
```
1. Double-cliquer run_server.bat     (Terminal 1)
2. Double-cliquer run_gui.bat        (Terminal 2)
3. Entrer le mot de passe : demo123
4. Cliquer "Se connecter"
```

### Linux/Mac
```bash
./run_server.sh  &  # Terminal 1
./run_gui.sh         # Terminal 2
```

### Python direct (tous OS)
```powershell
$env:PYTHONPATH="$PWD"
python tools/run_server.py    # Terminal 1
python tools/run_gui.py       # Terminal 2
```

---

## 🔐 Sécurité

- **Chiffrement** : AES-256-GCM (authentifié)
- **Dérivation Clé** : PBKDF2-HMAC-SHA256 (100K itérations)
- **Authentification** : Challenge-Response HMAC
- **Anti-Bruteforce** : 3 tentatives = 60s ban
- **Transfert Fichiers** : Chunk-based (4KB) avec SHA256

---

## 📊 Modules & Responsabilités

| Module | Role | Tests |
|--------|------|-------|
| `core/crypto` | Chiffrement AES-256-GCM + PBKDF2 | `test_crypto.py` |
| `core/protocol` | Framing TCP + Message enum | Intégré aux clients |
| `core/exceptions` | Exceptions personnalisées | Intégré aux modules |
| `servers/server` | Multi-client + Auth HMAC | `test_complete.py` |
| `servers/client_gui` | Interface Tkinter pro | Tests manuels |
| `servers/file_transfer` | Transfert sécurisé chunks | `test_file_transfer.py` |

---

## 🛠️ Développement

### Ajouter une nouvelle feature
1. Décider du module cible (core/, servers/, tools/)
2. Éditer le fichier approprié
3. Ajouter des tests dans tests/
4. Tester avec PYTHONPATH défini

### Importer des modules
```python
# ✅ Correct (depuis n'importe où avec PYTHONPATH défini)
from core.crypto import chiffrer
from servers.client import se_connecter
from servers.server import ValiderAuthentification

# ❌ Incorrect (imports relatifs à la racine)
from crypto import chiffrer  # ModuleNotFoundError
```

### Configuration Python
```powershell
# Toujours ajouter au PYTHONPATH avant d'exécuter
$env:PYTHONPATH="$PWD"
python script.py
```

---

## 📝 Résumé des Changements Récents

- ✅ Réorganisation en 5 répertoires logiques
- ✅ Tous les imports mis à jour (`core.`, `servers.`, etc.)
- ✅ Scripts launchers `.bat` et `.sh` créés
- ✅ Documentation QUICKSTART ajoutée
- ✅ `.env.example` pour configuration facile
- ✅ Tests passent tous avec PYTHONPATH

---

## 🎯 Prochaines Étapes

- [ ] Créer `demo_auto.py` pour démo sans interaction
- [ ] Ajouter mode "dark mode" à la GUI (done ✓)
- [ ] Créer Docker image pour déploiement
- [ ] Documentation API complète

---

**Dernière mise à jour** : Réorganisation post-nettoyage  
**Version** : 1.0 (Production-Ready)
