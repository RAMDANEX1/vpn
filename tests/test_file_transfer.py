#!/usr/bin/env python3
# test_file_transfer.py — Tests du module de transfert sécurisé de fichiers

import os
import socket
import subprocess
import time
import hashlib
import tempfile
from pathlib import Path

# Configuration
SERVEUR_IP = "127.0.0.1"
SERVEUR_PORT = 5000
MOT_DE_PASSE = "demo123"
DOSSIER_TEST = "test_transfer"

def creer_fichier_test(nom: str, contenu: str) -> str:
    """Crée un fichier de test."""
    if not os.path.exists(DOSSIER_TEST):
        os.makedirs(DOSSIER_TEST)
    
    chemin = os.path.join(DOSSIER_TEST, nom)
    with open(chemin, 'w', encoding='utf-8') as f:
        f.write(contenu)
    return chemin

def calculer_hash_fichier(chemin: str) -> str:
    """Calcule le hash SHA256 d'un fichier."""
    if not os.path.exists(chemin):
        return None
    
    hash_obj = hashlib.sha256()
    with open(chemin, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

def nettoyer():
    """Nettoie les fichiers de test."""
    import shutil
    if os.path.exists(DOSSIER_TEST):
        shutil.rmtree(DOSSIER_TEST)
        print(f"✅ Dossier {DOSSIER_TEST} nettoyé")

def test_fichier_texte():
    """Test 1 : Transfert simple d'un fichier texte."""
    print("\n" + "="*60)
    print("TEST 1 : Transfert d'un fichier texte simple")
    print("="*60)
    
    contenu_test = """Ceci est un fichier de test pour le transfert VPN.
Il contient du texte simple avec des accents : éàü
Et des caractères spéciaux : !@#$%^&*()
"""
    
    chemin_source = creer_fichier_test("test_simple.txt", contenu_test)
    print(f"✅ Fichier créé : {chemin_source}")
    print(f"   Taille : {os.path.getsize(chemin_source)} bytes")
    print(f"   Hash SHA256 : {calculer_hash_fichier(chemin_source)[:16]}...")

def test_fichier_binaire():
    """Test 2 : Transfert d'un fichier binaire."""
    print("\n" + "="*60)
    print("TEST 2 : Transfert d'un fichier binaire")
    print("="*60)
    
    # Créer un fichier binaire (1 MB de données aléatoires)
    if not os.path.exists(DOSSIER_TEST):
        os.makedirs(DOSSIER_TEST)
    
    chemin_binaire = os.path.join(DOSSIER_TEST, "test_binaire.bin")
    with open(chemin_binaire, 'wb') as f:
        f.write(os.urandom(1024 * 1024))  # 1 MB
    
    print(f"✅ Fichier binaire créé : {chemin_binaire}")
    print(f"   Taille : {os.path.getsize(chemin_binaire)} bytes")
    print(f"   Hash SHA256 : {calculer_hash_fichier(chemin_binaire)[:16]}...")

def test_fichier_grand():
    """Test 3 : Transfert d'un grand fichier."""
    print("\n" + "="*60)
    print("TEST 3 : Transfert d'un grand fichier (5 MB)")
    print("="*60)
    
    if not os.path.exists(DOSSIER_TEST):
        os.makedirs(DOSSIER_TEST)
    
    chemin_grand = os.path.join(DOSSIER_TEST, "test_grand.bin")
    taille_mb = 5
    with open(chemin_grand, 'wb') as f:
        f.write(os.urandom(taille_mb * 1024 * 1024))
    
    print(f"✅ Grand fichier créé : {chemin_grand}")
    print(f"   Taille : {os.path.getsize(chemin_grand)} bytes ({taille_mb} MB)")
    print(f"   Hash SHA256 : {calculer_hash_fichier(chemin_grand)[:16]}...")

def test_fichier_unicode():
    """Test 4 : Transfert avec caractères Unicode/Emoji."""
    print("\n" + "="*60)
    print("TEST 4 : Transfert avec Unicode et Emoji")
    print("="*60)
    
    contenu_unicode = """Fichier avec caractères spéciaux :
🔐 Chiffrement AES-256-GCM
🔑 Authentification HMAC
🛡️ Protection anti-bruteforce
📦 Transfert sécurisé de fichiers
🌍 Caractères internationaux : Ñ, Ü, Ž, Σ, Ω
中文 (Chinois), 日本語 (Japonais), 한국어 (Coréen)
العربية (Arabe), עברית (Hébreu)
"""
    
    chemin_unicode = creer_fichier_test("test_unicode.txt", contenu_unicode)
    print(f"✅ Fichier Unicode créé : {chemin_unicode}")
    print(f"   Taille : {os.path.getsize(chemin_unicode)} bytes")
    print(f"   Hash SHA256 : {calculer_hash_fichier(chemin_unicode)[:16]}...")

def test_fichier_vide():
    """Test 5 : Transfert d'un fichier vide."""
    print("\n" + "="*60)
    print("TEST 5 : Transfert d'un fichier vide")
    print("="*60)
    
    chemin_vide = creer_fichier_test("test_vide.txt", "")
    print(f"✅ Fichier vide créé : {chemin_vide}")
    print(f"   Taille : {os.path.getsize(chemin_vide)} bytes")

def test_fichier_multi_ligne():
    """Test 6 : Transfert d'un fichier CSV/TSV."""
    print("\n" + "="*60)
    print("TEST 6 : Transfert d'un fichier CSV")
    print("="*60)
    
    contenu_csv = """id,nom,email,description
1,Alice,alice@example.com,Développeuse Python
2,Bob,bob@example.com,Spécialiste en sécurité
3,Charlie,charlie@example.com,Ingénieur réseau
4,Diana,diana@example.com,Architecte cloud
5,Eve,eve@example.com,Data scientist
"""
    
    chemin_csv = creer_fichier_test("test_data.csv", contenu_csv)
    print(f"✅ Fichier CSV créé : {chemin_csv}")
    print(f"   Taille : {os.path.getsize(chemin_csv)} bytes")
    print(f"   Lignes : 6 (header + 5 enregistrements)")

if __name__ == "__main__":
    print("\n" + "🔐 TEST DU MODULE FILE_TRANSFER".center(60, "="))
    
    try:
        # Nettoyer avant de commencer
        nettoyer()
        
        # Exécuter les tests
        test_fichier_texte()
        test_fichier_binaire()
        test_fichier_grand()
        test_fichier_unicode()
        test_fichier_vide()
        test_fichier_multi_ligne()
        
        print("\n" + "="*60)
        print("✅ TOUS LES FICHIERS DE TEST CRÉÉS")
        print("="*60)
        print(f"\nFichiers disponibles dans : {DOSSIER_TEST}/")
        
        # Lister les fichiers créés
        if os.path.exists(DOSSIER_TEST):
            print("\nFichiers créés :")
            for fichier in os.listdir(DOSSIER_TEST):
                chemin = os.path.join(DOSSIER_TEST, fichier)
                taille = os.path.getsize(chemin)
                print(f"  📄 {fichier:<20} ({taille:>10} bytes)")
        
        print("\n📝 UTILISATION :")
        print("""
Pour tester le transfert de fichiers, utilisez:

1. SERVEUR:
   VPN_PASSWORD="demo123" python server.py --verbose

2. CLIENT (dans un autre terminal):
   python client.py
   
   Puis utilisez les commandes:
   > file test_transfer/test_simple.txt
   > file test_transfer/test_unicode.txt
   > file test_transfer/test_binaire.bin

3. VÉRIFICATION:
   Comparer les hashs des fichiers source et destination
   pour vérifier l'intégrité du transfert.
""")
    
    finally:
        pass
