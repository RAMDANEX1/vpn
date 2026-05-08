#!/usr/bin/env python3
# run_server.py — Launcher facile pour le serveur VPN avec mot de passe sécurisé

import os
import sys
import subprocess
import getpass

def main():
    print("=" * 60)
    print("[VPN] SERVEUR VPN - Launcher Securise")
    print("=" * 60)
    
    # Demander le mot de passe interactivement
    print("\n[INPUT] Entrez le mot de passe pour le serveur VPN:")
    password = getpass.getpass("Mot de passe: ")
    
    if not password:
        print("[ERROR] Mot de passe vide, arret.")
        sys.exit(1)
    
    # Demander les paramètres optionnels
    print("\n[CONFIG] Parametres optionnels (appuyez sur Entree pour les defauts):")
    
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
        print("[ERROR] Entree invalide.")
        sys.exit(1)
    
    # Définir la variable d'environnement
    os.environ["VPN_PASSWORD"] = password
    
    # Afficher la configuration
    print("\n" + "=" * 60)
    print("[OK] Configuration du serveur:")
    print(f"   [PASSWORD] Mot de passe : {'*' * len(password)}")
    print(f"   [PORT] Port : {port}")
    print(f"   [LOG] Log level : {log_level}")
    print(f"   [CLIENTS] Max clients : {max_clients}")
    print("=" * 60)
    
    input("\n[WAIT] Appuyez sur Entree pour demarrer le serveur...")
    
    # Lancer le serveur
    try:
        cmd = [
            "python", "servers/server.py",
            "--port", str(port),
            "--log-level", log_level,
            "--max-clients", str(max_clients)
        ]
        print(f"\n[START] Lancement : {' '.join(cmd)}\n")
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        print("\n\n[STOP] Serveur arrete.")
    except Exception as e:
        print(f"[ERROR] Erreur : {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
