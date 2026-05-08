# 🎬 Script de Démonstration — Mini VPN Chiffré

## Temps total : 15 minutes

---

## 📝 AVANT LA DÉMO

✅ Installer les dépendances
```bash
pip install -r requirements.txt
```

✅ Télécharger Wireshark (optionnel mais recommandé)
- https://www.wireshark.org/download

✅ Préparer 3-4 terminaux PowerShell/Terminal

---

## 🎯 DÉMO EN 5 ACTES

### **ACTE 1 : Présentation du Projet (2 min)**

**Dire :**
> *"Ceci est un Mini VPN éducatif qui montre les principes de tunnélisation VPN et de chiffrement."*
> *"Architecture :"*
> - **Client** : Interface CLI ou GUI Tkinter
> - **Serveur** : Multi-client avec authentification HMAC
> - **Transport** : TCP chiffré AES-256-GCM
> - **Sécurité** : Mot de passe protégé par PBKDF2 (100k itérations)

**Afficher le diagramme mentalement :**
```
Client GUI/CLI 
    ↓ (Chiffré AES-256-GCM)
Port 5000 TCP
    ↓ (Authentification HMAC Challenge-Response)
Serveur VPN
```

---

### **ACTE 2 : Lancer l'Infrastructure (2 min)**

**Terminal 1 - Serveur :**
```bash
cd c:\Users\rmdzv\OneDrive\Bureau\vpn
VPN_PASSWORD="demo123" python server.py --verbose
```

**Attendre le message :**
```
✅ Serveur VPN lancé sur 127.0.0.1:5000
```

**Terminal 2 - Lancer Wireshark (optionnel) :**
1. Ouvrir Wireshark
2. Sélectionner interface "Loopback" ou "Ethernet"
3. Cliquer Capture → Start
4. Appliquer le filtre : `tcp.port == 5000`

---

### **ACTE 3 : Test d'Authentification ÉCHOUÉE (2 min)**

**Terminal 3 - Client :**
```bash
# Comparer les hashs SHA256
Get-FileHash test_transfer/test_simple.txt -Algorithm SHA256
Get-FileHash received_files/test_simple.txt -Algorithm SHA256
# Entrer quand demandé :
# Serveur IP: localhost
# Serveur Port: 5000
# Mot de passe: wrong_password
```

**Attendre les 3 tentatives échouées :**
```
❌ Authentification échouée (Tentative 1/3)
❌ Authentification échouée (Tentative 2/3)
❌ Authentification échouée (Tentative 3/3)
⛔ Vous avez dépassé le nombre maximum de tentatives. Bannissement 60s.
```

**Dire :**
> *"Nous voyons ici la protection anti-bruteforce. Après 3 tentatives échouées, le client est banni pendant 60 secondes."*

---

### **ACTE 4 : Authentification RÉUSSIE + Envoi de Messages (3 min)**

**Terminal 3 - Nouveau client :**
```bash
python client.py
# Entrer :
# Serveur IP: localhost
# Serveur Port: 5000
# Mot de passe: demo123
```

**Message d'authentification :**
```
🔓 Authentification réussie!
Connecté au serveur VPN.
Tapez votre message (ou 'quit' pour sortir):
```

**Envoyer 3 messages de test :**
```
> Ceci est le message 1 - chiffré avec AES-256-GCM
> Message 2 avec des caractères spéciaux : éàü 😀
> Message 3 - testons la compression zlib
```

**Observer :**
- Messages sont affichés avec timestamps
- Aucun message n'est visible en clair sur le réseau (sauf si observé sur Wireshark)

**Dire :**
> *"Tous ces messages sont chiffrés en AES-256-GCM. Même en écoutant le réseau, un attaquant ne verrait que du binaire aléatoire."*

---

### **ACTE 5 : GUI Client (2 min)**

**Terminal 4 - Client GUI :**
```bash
python client_gui.py
```

**Dans la GUI :**
1. **IP Serveur :** 127.0.0.1 ✓
2. **Port :** 5000 ✓
3. **Mot de passe :** demo123 ✓
4. Cliquer **"Se connecter"**

**Envoyer messages dans la GUI :**
```
Test du GUI Tkinter 1
Test du GUI Tkinter 2 - avec timestamps
Test du GUI Tkinter 3 - interface professionnelle
```

**Montrer :**
- Chaque message a un timestamp exact
- Bouton de déconnexion explicite
- Zone de texte scrollable pour de longs messages

---

### **ACTE 6 : Analyse Wireshark (2 min)**

**Si Wireshark est actif :**

1. **Arrêter la capture** (carré rouge dans Wireshark)

2. **Observer les paquets :**
   - Filtre appliqué : `tcp.port == 5000`
   - Voir la séquence TCP :
     - [SYN] Établissement connexion
     - [ACK, PSH] Challenge HMAC (données chiffrées)
     - [ACK, PSH] Réponse HMAC
     - [PSH] Messages chiffrés

3. **Pointer les caractéristiques :**
   - ✅ Les données sont **du binaire aléatoire** (pas lisible)
   - ✅ Chaque paquet a un header de framing (2 octets : taille)
   - ✅ Pas de mot de passe visible en clair

4. **Exporter la capture (optionnel) :**
   - File → Export Packet Dissections → As CSV
   - Sauvegarder pour le rapport

**Dire :**
> *"Wireshark montre que même en capturant tous les paquets réseau, on ne voit que du charabia chiffré. C'est l'objectif principal d'un VPN."*

---

### **ACTE 7 : Tests Automatisés (2 min)**

**Terminal 5 :**
```bash
# Test cryptographique
python test_crypto.py
```

**Résultats attendus :**
```
✓ Roundtrip chiffrement/déchiffrement
✓ IV aléatoire (pas de déterminisme)
✓ Rejet des mots de passe incorrects
✓ Détection des paquets corrompus
✓ Compression zlib
✓ Support Unicode/Emojis
✓ Dérivation PBKDF2

Tous les tests passent ✅
```

**Optionnel :**
```bash
python test_complete.py      # Test intégration complète
python test_security.py      # Test sécurité bruteforce
```

---

## 🎓 POINTS CLÉS À SOULIGNER

### **1. Chiffrement Authentifié**
- AES-256-GCM = chiffrement + authentification
- Si un bit change, la déchiffrement échoue automatiquement

### **2. Authentification HMAC Challenge-Response**
- Mot de passe jamais envoyé en clair
- Server envoie un "défi", client répond avec HMAC(password, défi)
- Résiste aux écoutes réseau

### **3. Dérivation Clé PBKDF2**
- Mot de passe faible → rendu fort par 100k itérations SHA256
- Ralentit les attaques par bruteforce

### **4. Framing TCP**
- TCP peut fragmenter les données
- Notre protocole ajoute un header de longueur
- Garantit l'intégrité du message

### **5. Multi-client**
- Le serveur gère plusieurs clients simultanément avec threading
- Chacun a sa propre clé de session

---

## 📊 STATISTIQUES À CITER

- **Clé AES** : 256 bits (32 octets)
- **IV** : 12 octets (recommandé pour GCM)
- **Tag d'authentification** : 16 octets
- **Overhead par message** : ~18 octets + framing
- **Itérations PBKDF2** : 100 000
- **Temps d'authentification** : < 1 seconde

---

## 🔴 ATTENTION : Pièges à Éviter

❌ Ne pas lancer le client/GUI avant le serveur
❌ Ne pas oublier `VPN_PASSWORD=...` pour le serveur
❌ Ne pas fermer les terminaux au hasard
❌ Si erreur "Port already in use" → changez le port dans config.py
❌ Si Wireshark ne capture rien → vérifier l'interface réseau

---

## ✅ CHECKLIST PRÉ-DÉMO

- [ ] Serveur prêt à démarrer
- [ ] Dépendances installées (pip install -r requirements.txt)
- [ ] Wireshark installé et configuré (optionnel)
- [ ] 3-4 terminaux ouverts
- [ ] Fichiers test_*.py à proximité pour la démo bonus
- [ ] Rapport/slides préparés

---

## 🎬 DURÉE ESTIMÉE

| Acte | Temps |
|------|-------|
| 1. Présentation | 2 min |
| 2. Infrastructure | 2 min |
| 3. Auth échouée | 2 min |
| 4. Auth réussie | 3 min |
| 5. GUI Client | 2 min |
| 6. Wireshark | 2 min |
| 7. Tests | 2 min |
| **TOTAL** | **~15 min** |

**+ 5 min** pour questions/discussions

---

**Bonne démo! 🎉**
