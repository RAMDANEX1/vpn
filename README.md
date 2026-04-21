# Mini VPN Éducatif

Simulation d'un tunnel VPN chiffré en Python — Projet L2/DUT2.

## Installation

```bash
pip install pycryptodome
```

## Lancer le projet

**Terminal 1 (serveur) :**
```bash
python3 server.py
```

**Terminal 2 (client) :**
```bash
python3 client.py
```

## Tester le chiffrement

```bash
python3 test_crypto.py
```

## Structure

```
mini-vpn/
├── config.py        ← réglages partagés (IP, port, mot de passe)
├── crypto.py        ← chiffrement AES-256-GCM
├── server.py        ← serveur TCP avec auth
├── client.py        ← client TCP avec auth
├── test_crypto.py   ← tests unitaires crypto
└── rapport/         ← rapport et slides
```

## Équipe

- M1 : Chef projet + rapport
- M2 : Cryptographie (crypto.py)
- M3 : Serveur (server.py)
- M4 : Client + tests (client.py)
