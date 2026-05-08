# 📦 Guide Complet — Test du Transfert de Fichiers

## 🎯 Vue d'ensemble

Le module `file_transfer.py` implémente un **transfert sécurisé de fichiers via le tunnel VPN** avec :
- ✅ Chiffrement **AES-256-GCM**
- ✅ Support des fichiers **binaires** et **texte**
- ✅ **Chunking** (envoi par morceaux de 4 KB)
- ✅ **Barre de progression** en temps réel
- ✅ **Vérification d'intégrité** (hash SHA256)
- ✅ Support **Unicode/Emoji**

---

## 📋 Préparation

### 1. Créer les fichiers de test

```bash
python test_file_transfer.py
```

Cela crée un dossier `test_transfer/` avec :
- `test_simple.txt` (texte simple)
- `test_binaire.bin` (1 MB aléatoire)
- `test_grand.bin` (5 MB aléatoire)
- `test_unicode.txt` (Emoji, CJK, etc.)
- `test_vide.txt` (0 bytes)
- `test_data.csv` (données CSV)

### 2. Vérifier le hash initial

```bash
# Pour chaque fichier, notez le hash SHA256
Get-FileHash test_transfer/test_simple.txt -Algorithm SHA256
```

---

## 🚀 Étapes du Test

### **ÉTAPE 1 : Lancer le Serveur**

```bash
# Terminal 1
VPN_PASSWORD="demo123" python server.py --verbose
```

Attendre :
```
✅ Serveur VPN lancé sur 127.0.0.1:5000
```

---

### **ÉTAPE 2 : Lancer le Client**

```bash
# Terminal 2
python client.py
```

Quand demandé :
```
Serveur IP: localhost
Serveur Port: 5000
Mot de passe: demo123
```

Attendre :
```
🔓 Authentification réussie!
Connecté au serveur VPN.
Tapez votre message (ou 'quit' pour sortir):
```

---

### **ÉTAPE 3 : Envoyer un Fichier**

Dans le client, taper la commande :

```bash
# Syntaxe : file <chemin_du_fichier>
file test_transfer/test_simple.txt
```

**Résultat attendu :**
```
[FICHIER] Envoi de 'test_simple.txt' (245 bytes)...
[FICHIER] 245/245 bytes (100%)
[FICHIER] 'test_simple.txt' envoyé avec succès
```

---

### **ÉTAPE 4 : Vérifier le Fichier Reçu**

Sur le **serveur**, vérifier que le fichier a été reçu :

```bash
# Sur le Terminal 1 (serveur), vous devriez voir :
[FICHIER] Réception de 'test_simple.txt' (245 bytes)...
[FICHIER] 245/245 bytes (100%)
[FICHIER] 'test_simple.txt' reçu avec succès dans received_files/
```

---

### **ÉTAPE 5 : Comparer les Hashs**

Vérifier que le fichier a été transféré **sans corruption** :

```bash
# Hash du fichier original
Get-FileHash test_transfer/test_simple.txt -Algorithm SHA256

# Hash du fichier reçu sur le serveur
Get-FileHash received_files/test_simple.txt -Algorithm SHA256
```

✅ **Les deux hashs doivent être IDENTIQUES**

---

## 📊 Scénarios de Test Complets

### **Test 1 : Fichier Texte Simple**

```bash
# Client
file test_transfer/test_simple.txt

# Vérifier
Get-FileHash test_transfer/test_simple.txt -Algorithm SHA256
Get-FileHash received_files/test_simple.txt -Algorithm SHA256
```

**Points à vérifier :**
- ✅ Affichage de la barre de progression
- ✅ Message "envoyé avec succès"
- ✅ Hashs identiques

---

### **Test 2 : Fichier Binaire (1 MB)**

```bash
# Client
file test_transfer/test_binaire.bin

# Vérifier
Get-FileHash test_transfer/test_binaire.bin -Algorithm SHA256
Get-FileHash received_files/test_binaire.bin -Algorithm SHA256
```

**Points à vérifier :**
- ✅ Barre de progression fluide
- ✅ Environ 250+ chunks (4 KB chacun)
- ✅ Hashs identiques (intégrité binaire)

---

### **Test 3 : Grand Fichier (5 MB)**

```bash
# Client
file test_transfer/test_grand.bin

# Observer la progression en temps réel
# Devrait afficher : 0/5242880 bytes (0%)
#                  5242880/5242880 bytes (100%)

# Vérifier
Get-FileHash test_transfer/test_grand.bin -Algorithm SHA256
Get-FileHash received_files/test_grand.bin -Algorithm SHA256
```

**Points à vérifier :**
- ✅ Temps de transfert raisonnable (30-60s selon la machine)
- ✅ Hashs identiques
- ✅ Pas de timeout ou disconnexion

---

### **Test 4 : Fichier avec Unicode/Emoji**

```bash
# Client
file test_transfer/test_unicode.txt

# Vérifier le contenu
type received_files/test_unicode.txt

# Vérifier hash
Get-FileHash test_transfer/test_unicode.txt -Algorithm SHA256
Get-FileHash received_files/test_unicode.txt -Algorithm SHA256
```

**Points à vérifier :**
- ✅ Emoji affichés correctement 🔐🔑🛡️
- ✅ Caractères internationaux préservés
- ✅ Hashs identiques

---

### **Test 5 : Fichier Vide**

```bash
# Client
file test_transfer/test_vide.txt

# Vérifier
Get-FileHash test_transfer/test_vide.txt -Algorithm SHA256
Get-FileHash received_files/test_vide.txt -Algorithm SHA256
```

**Points à vérifier :**
- ✅ Pas d'erreur
- ✅ Fichier créé (0 bytes) sur le serveur
- ✅ Hashs identiques

---

### **Test 6 : Fichier CSV (Données)**

```bash
# Client
file test_transfer/test_data.csv

# Vérifier le contenu
type received_files/test_data.csv

# Résultat attendu :
# id,nom,email,description
# 1,Alice,alice@example.com,Développeuse Python
# ...
```

**Points à vérifier :**
- ✅ Structure CSV préservée
- ✅ Sauts de ligne intacts
- ✅ Hashs identiques

---

## 🔍 Tests Avancés

### **Test 7 : Transferts Multiples en Succession**

```bash
# Client, envoyer plusieurs fichiers d'affilée
file test_transfer/test_simple.txt
file test_transfer/test_unicode.txt
file test_transfer/test_binaire.bin
```

**Points à vérifier :**
- ✅ Pas d'erreur après le 1er transfert
- ✅ Connexion reste stable
- ✅ Tous les fichiers arrivent correctement

---

### **Test 8 : Transfert Pendant Wireshark**

```bash
# Terminal 1 : Serveur
VPN_PASSWORD="demo123" python server.py

# Terminal 2 : Wireshark
# Filtre: tcp.port == 5000
# Capture Start

# Terminal 3 : Client
python client.py
file test_transfer/test_binaire.bin

# Arrêter Wireshark après le transfert
# Observer : paquets de taille ~4 KB (chunks)
```

**Points à vérifier :**
- ✅ Voir les chunks chiffrés dans Wireshark
- ✅ Chaque paquet contient ~4 KB de données (+ header chiffré)
- ✅ Aucune donnée lisible en clair

---

### **Test 9 : Espace Disque Limité**

```bash
# Créer un fichier du même type que test_transfer/
# Mais plus petit pour tester les limites

# Si le serveur manque d'espace, le transfert échouera
# Le message d'erreur devrait indiquer l'espace manquant
```

---

## 📈 Métriques à Capter

Pendant les tests, notez :

| Métrique | Fichier Simple | Binaire 1MB | Grand 5MB |
|----------|---|---|---|
| Taille (bytes) | 245 | 1 048 576 | 5 242 880 |
| Nombre de chunks | 1 | 256 | 1 280 |
| Temps de transfert | <1s | 2-5s | 10-30s |
| Barre progression | Oui | Oui | Oui |
| Hash match | ✅ | ✅ | ✅ |

---

## 🛡️ Intégrité et Sécurité

### Vérification Hash (SHA256)

```bash
# PowerShell
function Test-FileIntegrity {
    param([string]$OriginalFile, [string]$ReceivedFile)
    
    $hash1 = (Get-FileHash $OriginalFile -Algorithm SHA256).Hash
    $hash2 = (Get-FileHash $ReceivedFile -Algorithm SHA256).Hash
    
    if ($hash1 -eq $hash2) {
        Write-Host "✅ INTÉGRITÉ VÉRIFIÉE: Les fichiers sont identiques"
        return $true
    } else {
        Write-Host "❌ CORRUPTION: Les hashs ne correspondent pas!"
        Write-Host "Fichier original:    $hash1"
        Write-Host "Fichier reçu:        $hash2"
        return $false
    }
}

# Utilisation
Test-FileIntegrity "test_transfer/test_binaire.bin" "received_files/test_binaire.bin"
```

---

## ⚠️ Cas d'Erreur (À Tester)

### Test 10 : Fichier Introuvable

```bash
# Client
file nonexistent_file.txt

# Résultat attendu :
# [ERREUR] Fichier introuvable : nonexistent_file.txt
```

---

### Test 11 : Déconnexion Pendant le Transfert

```bash
# Client, pendant un transfert de grand fichier :
file test_transfer/test_grand.bin

# Appuyer Ctrl+C après quelques secondes

# Résultat attendu :
# [ERREUR] Connexion interrompue
# Serveur doit se nettoyer et rester stable
```

---

## 📝 Rapport de Test

Créer un fichier `TEST_REPORT_FILE_TRANSFER.md` avec :

```markdown
# Rapport de Test — File Transfer

## Configuration
- Serveur : 127.0.0.1:5000
- Mot de passe : demo123
- Date : [DATE]

## Résultats

### Test 1 : Fichier Texte
- ✅ Status : RÉUSSI
- Taille : 245 bytes
- Hash OK : ✅
- Temps : <1s

### Test 2 : Binaire 1MB
- ✅ Status : RÉUSSI
- Taille : 1,048,576 bytes
- Hash OK : ✅
- Temps : 3s
- Chunks : 256

### [...]

## Conclusion
Tous les tests passent ✅
Le module file_transfer est production-ready.
```

---

## 🎬 Démo Live

```bash
# Montrer le transfert en direct :
echo "Création d'un fichier de démonstration..."
> demo_file.txt echo "Ceci est un fichier de démonstration pour la démo live"

# Serveur
VPN_PASSWORD="demo123" python server.py --verbose

# Client (dans un autre terminal)
python client.py

# Envoyer le fichier
file demo_file.txt

# Montrer qu'il est reçu sur le serveur
type received_files/demo_file.txt

# Vérifier le hash
Get-FileHash demo_file.txt -Algorithm SHA256
Get-FileHash received_files/demo_file.txt -Algorithm SHA256
```

---

## ✅ Checklist Pré-Test

- [ ] Dépendances installées : `pip install -r requirements.txt`
- [ ] Fichiers de test créés : `python test_file_transfer.py`
- [ ] Hashs initiaux notés
- [ ] Dossier `received_files/` accessible sur le serveur
- [ ] Wireshark installé (optionnel)
- [ ] 2-3 terminaux ouverts

---

**Bonne chance avec les tests! 🚀**
