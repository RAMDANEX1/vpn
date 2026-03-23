# Rapport Mini-VPN

## 1. Objectif
Realiser un mini VPN de demonstration avec chiffrement symetrique.

## 2. Architecture
- client.py : envoie des messages chiffres
- server.py : recoit, dechiffre et repond
- crypto.py : fonctions `chiffrer()` et `dechiffrer()`
- config.py : configuration reseau et cle partagee

## 3. Choix techniques
- Socket TCP pour la communication
- Chiffrement par flux XOR derive de SHA-256
- HMAC-SHA256 pour verifier l'integrite

## 4. Tests
Lancer :

```bash
python -m unittest test_crypto.py
```

## 5. Demo
1. Lancer le serveur
2. Lancer le client
3. Envoyer des messages
4. Capturer les ecrans dans `rapport/captures/`

## 6. Conclusion
Le projet valide une communication client/serveur avec chiffrement et verification d'integrite.
