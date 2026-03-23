# mini-vpn (dans le dossier vpn)

Structure creee:

- config.py
- crypto.py
- server.py
- client.py
- test_crypto.py
- .gitignore
- rapport/rapport.md
- rapport/slides.pptx
- rapport/captures/

## Demarrage

1. Lancer le serveur:

```bash
python server.py
```

2. Dans un autre terminal, lancer le client:

```bash
python client.py
```

3. Tester le chiffrement:

```bash
python -m unittest test_crypto.py
```

