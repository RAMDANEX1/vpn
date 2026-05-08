# 🔧 FIX — Scripts de Lancement Corrigés

## Problème Identifié

Les fichiers `.bat` (`run_server.bat` et `run_gui.bat`) ne fonctionnaient pas avec l'erreur :

```
python: can't open file 'C:\Users\rmdzv\OneDrive\Bureau\tools\run_server.py': [Errno 2] No such file or directory
```

### Cause Racine

Le script utilisait un chemin incorrect :

```batch
cd /d "%~dp0\.."    # Remonte un répertoire trop haut !
```

**Résultat :**
- `%~dp0` = `C:\Users\rmdzv\OneDrive\Bureau\vpn\`
- `%~dp0\..` = `C:\Users\rmdzv\OneDrive\Bureau\` ❌ (MAUVAIS!)
- Cherche : `C:\Users\rmdzv\OneDrive\Bureau\tools\run_server.py` ❌

---

## Solution Appliquée

### Fichiers .bat Corrigés

**AVANT :**
```batch
@echo off
cd /d "%~dp0\.."
set PYTHONPATH=%CD%
python tools/run_server.py
```

**APRÈS :**
```batch
@echo off
cd /d "%~dp0"          # Reste dans vpn/ au lieu de remonter
set PYTHONPATH=%CD%
python tools/run_server.py
```

**Résultat :**
- `cd /d "%~dp0"` = `C:\Users\rmdzv\OneDrive\Bureau\vpn\` ✅
- Cherche : `C:\Users\rmdzv\OneDrive\Bureau\vpn\tools\run_server.py` ✅

### Fichiers Modifiés

| Fichier | Change |
|---------|--------|
| `run_server.bat` | `cd /d "%~dp0\.."` → `cd /d "%~dp0"` |
| `run_gui.bat` | `cd /d "%~dp0%"` → `cd /d "%~dp0"` |
| `run_server.sh` | ✅ Déjà correct |
| `run_gui.sh` | ✅ Déjà correct |

### Bonus : Encodage UTF-8

Correction aussi dans `tools/run_server.py` :
- ❌ Avant : Emojis (🔐, 📝, ❌, etc.) → Erreur `UnicodeEncodeError`
- ✅ Après : Texte ASCII ([VPN], [INPUT], [ERROR], etc.) → Fonctionne sur Windows

---

## Vérification Post-Fix

```powershell
# Test 1: Script exécutable
$env:PYTHONPATH="$PWD"
python tools/run_server.py

# Résultat: Demande le mot de passe ✅ (pas d'erreur de chemin)
```

### Chemins Vérifiés

| Élément | Chemin |
|---------|--------|
| run_server.bat | `C:\Users\rmdzv\OneDrive\Bureau\vpn\` |
| tools/run_server.py | `C:\Users\rmdzv\OneDrive\Bureau\vpn\tools\run_server.py` |
| PYTHONPATH | `C:\Users\rmdzv\OneDrive\Bureau\vpn` |

---

## Comment Utiliser

### Windows (Double-clic)

```
1. Aller dans C:\Users\rmdzv\OneDrive\Bureau\vpn\
2. Double-clic sur run_server.bat
3. Le terminal s'ouvre et demande le mot de passe
4. Entrer le mot de passe et appuyer sur Entrée
5. Le serveur démarre
```

### PowerShell

```powershell
cd C:\Users\rmdzv\OneDrive\Bureau\vpn
$env:PYTHONPATH="$PWD"
python tools/run_server.py
```

### Linux/Mac

```bash
cd ~/OneDrive/Bureau/vpn  # ou le chemin équivalent
./run_server.sh
```

---

## Tests Supplémentaires

Pour vérifier que les scripts fonctionnent correctement :

```powershell
# Test 1: Vérifier les fichiers existent
if (Test-Path tools/run_server.py) { "OK" }

# Test 2: Vérifier les imports
$env:PYTHONPATH="$PWD"
python -c "from servers.server import *; print('OK')"

# Test 3: Exécuter le script (il demandera le mot de passe)
python tools/run_server.py
```

---

## Résumé des Corrections

| Problème | Cause | Solution | Statut |
|----------|-------|----------|--------|
| Chemin incorrect | `%~dp0\..` remonte trop | Utiliser `%~dp0` | ✅ Fixed |
| Emojis en encoding | Windows cp1252 | Remplacer par ASCII | ✅ Fixed |
| Script .bat ne trouve pas fichiers | Mauvais répertoire | Corriger `cd` | ✅ Fixed |
| Script .sh marche déjà | N/A | Rien à faire | ✅ OK |

---

**Date :** May 8, 2026  
**Status :** ✅ COMPLETEMENT CORRIGE
