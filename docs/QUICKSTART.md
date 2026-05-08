# 🚀 QUICKSTART — Démarrer en 3 Étapes

## Option 1️⃣ : Double-clic (😍 Le plus facile - Windows)

**Terminal 1 :**
```
Double-clic sur  →  run_server.bat
```

**Terminal 2 :**
```
Double-clic sur  →  run_gui.bat
```

Puis suivez les instructions à l'écran. ✨ Terminé !

---

## Option 2️⃣ : Terminal PowerShell

**Étape 1 : Installer les dépendances**
```powershell
cd c:\Users\rmdzv\OneDrive\Bureau\vpn
pip install -r requirements.txt
```

**Étape 2 : Lancer le Serveur (Terminal 1)**
```powershell
$env:PYTHONPATH="$PWD"
python tools/run_server.py
```

Répondre aux questions :
```
Mot de passe: demo123
Port [5000]: [Entrée]
Niveau de log [DEBUG]: [Entrée]
Max clients [10]: [Entrée]
```

**Étape 3 : Lancer le Client GUI (Terminal 2)**
```powershell
$env:PYTHONPATH="$PWD"
python tools/run_gui.py
```

Dans la GUI :
- IP Serveur: `127.0.0.1` ✅ (déjà rempli)
- Port: `5000` ✅ (déjà rempli)
- Mot de passe: `demo123`
- Cliquer **"✅ Se connecter"**

---

## ✅ Prêt ! 

La connexion est établie ! Vous pouvez maintenant :
- 💬 Envoyer des messages
- 📊 Voir les statistiques en temps réel
- 📁 Envoyer des fichiers
- 🔄 Tester le ping

---

## 🆘 Troubleshooting

### ❌ "Mot de passe incorrect"
→ Vérifier que vous avez bien entré **`demo123`** dans les deux (serveur ET client)

### ❌ "Connection refused"
→ Le serveur n'est pas lancé. Vérifier Terminal 1 pour voir l'erreur

### ❌ "Port already in use"
→ Un autre programme utilise le port 5000. Choisir un port différent (ex: 8888)

---

## 📚 Documentation Complète

- **[DEMO_SCRIPT.md](DEMO_SCRIPT.md)** — Script de démo détaillé (7 actes)
- **[GUIDE_FILE_TRANSFER.md](GUIDE_FILE_TRANSFER.md)** — Guide complet transfert fichiers
- **[README.md](README.md)** — Documentation technique complète

---

## 🎯 Commandes Rapides

```powershell
# Lancer serveur
python tools/run_server.py

# Lancer GUI client
python tools/run_gui.py

# Lancer client CLI (alternatif)
python servers/client.py

# Tester la crypto
python tests/test_crypto.py

# Tests complets
python tests/test_complete.py
```

---

**Besoin d'aide ?** Consultez les guides complets dans [docs/](docs/)
