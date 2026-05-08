#!/usr/bin/env python3
# run_server.py — Launcher facile pour le serveur VPN avec mot de passe sécurisé

import os
import sys
import subprocess
import getpass

def main():
    print("=" * 60)
    print("🔐 SERVEUR VPN — Launcher Sécurisé")
    print("=" * 60)
    
    # Demander le mot de passe interactivement
    print("\n📝 Entrez le mot de passe pour le serveur VPN:")
    password = getpass.getpass("Mot de passe: ")
    
    if not password:
        print("❌ Mot de passe vide, arrêt.")
        sys.exit(1)
    
    # Demander les paramètres optionnels
    print("\n⚙️  Paramètres optionnels (appuyez sur Entrée pour les défauts):")
    
    port = input("Port [5000]: ").strip() or "5000"
    log_level = input("Niveau de log [DEBUG]: ").strip() or "DEBUG"
    max_clients = input("Max clients [10]: ").strip() or "10"
    
    # Valider les entrées
    try:
        port = int(port)
        max_clients = int(max_clients)
        if log_level not in ["DEBUG", "INFO", "WARNING"]:
            log_level = "DEBUG"
    except ValueError:
        print("❌ Entrée invalide.")
        sys.exit(1)
    
    # Définir la variable d'environnement
    os.environ["VPN_PASSWORD"] = password
    
    # Afficher la configuration
    print("\n" + "=" * 60)
    print("✅ Configuration du serveur:")
    print(f"   🔐 Mot de passe : {'*' * len(password)}")
    print(f"   📡 Port : {port}")
    print(f"   📊 Log level : {log_level}")
    print(f"   👥 Max clients : {max_clients}")
    print("=" * 60)
    
    input("\n⏳ Appuyez sur Entrée pour démarrer le serveur...")
    
    # Lancer le serveur
    try:
        cmd = [
            "python", "server.py",
            "--port", str(port),
            "--log-level", log_level,
            "--max-clients", str(max_clients)
        ]
        print(f"\n🚀 Lancement : {' '.join(cmd)}\n")
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        print("\n\n⛔ Serveur arrêté.")
    except Exception as e:
        print(f"❌ Erreur : {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
