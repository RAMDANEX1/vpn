# client_gui.py — Client VPN éducatif avec interface graphique professionnelle (Tkinter)
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from datetime import datetime
from datetime import timedelta
import hmac
import os
import time
from core.config import SERVEUR_IP, SERVEUR_PORT, TAILLE_BUFFER
from core.crypto import chiffrer, dechiffrer
from core.protocol import envoyer, recevoir, emballer, deballer, TypeMessage


# 🎨 THÈME DARK MODE
THEME = {
    "bg_dark": "#1e1e1e",
    "bg_secondary": "#2d2d2d",
    "bg_tertiary": "#3a3a3a",
    "fg_light": "#ffffff",
    "fg_muted": "#b0b0b0",
    "accent_blue": "#007AFF",
    "success_green": "#34C759",
    "error_red": "#FF3B30",
    "warning_orange": "#FF9500",
    "stat_gold": "#FFD700"
}


class VpnClientGUI:
    def __init__(self, master):
        self.master = master
        master.title("🔐 Client VPN Chiffré — Mini VPN Éducatif")
        master.geometry("950x900")
        master.config(bg=THEME["bg_dark"])
        
        # Statistics tracking
        self.sock = None
        self.mot_de_passe = None
        self.connected = False
        self.start_time = None
        self.msg_sent = 0
        self.msg_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.last_ping_time = None
        self.latency_ms = 0
        self.activity_indicator = "⟳"
        
        # Build the UI
        self.create_widgets()
        
        master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self):
        """Crée tous les widgets de l'interface."""
        
        # ===== SECTION CONNEXION =====
        self.create_connection_section()
        
        # ===== SECTION STATUT =====
        self.create_status_section()
        
        # ===== CONTENEUR PRINCIPAL (Historique + Stats) =====
        main_container = tk.Frame(self.master, bg=THEME["bg_dark"])
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Historique des messages (à gauche)
        self.create_history_section(main_container)
        
        # Panneau stats (à droite)
        self.create_stats_panel(main_container)
        
        # ===== SECTION MESSAGES ET ACTIONS =====
        self.create_message_section()
        
        # ===== SECTION BOUTONS =====
        self.create_action_buttons()

    def create_connection_section(self):
        """Crée la section de connexion."""
        conn_frame = tk.Frame(self.master, bg=THEME["bg_secondary"], padx=15, pady=12)
        conn_frame.pack(fill=tk.X, padx=10, pady=(10, 5))
        
        # Colonne 1 : Inputs
        input_frame = tk.Frame(conn_frame, bg=THEME["bg_secondary"])
        input_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # IP
        tk.Label(input_frame, text="🌐 IP Serveur:", bg=THEME["bg_secondary"], fg=THEME["fg_light"], font=("Arial", 9, "bold")).grid(row=0, column=0, sticky=tk.W, padx=5)
        self.ip_entry = tk.Entry(input_frame, width=20, bg=THEME["bg_tertiary"], fg=THEME["fg_light"], insertbackground=THEME["fg_light"])
        self.ip_entry.grid(row=0, column=1, padx=5)
        self.ip_entry.insert(0, SERVEUR_IP)
        
        # Port
        tk.Label(input_frame, text="📡 Port:", bg=THEME["bg_secondary"], fg=THEME["fg_light"], font=("Arial", 9, "bold")).grid(row=0, column=2, sticky=tk.W, padx=5)
        self.port_entry = tk.Entry(input_frame, width=10, bg=THEME["bg_tertiary"], fg=THEME["fg_light"], insertbackground=THEME["fg_light"])
        self.port_entry.grid(row=0, column=3, padx=5)
        self.port_entry.insert(0, str(SERVEUR_PORT))
        
        # Mot de passe
        tk.Label(input_frame, text="🔐 Mot de passe:", bg=THEME["bg_secondary"], fg=THEME["fg_light"], font=("Arial", 9, "bold")).grid(row=0, column=4, sticky=tk.W, padx=5)
        self.password_entry = tk.Entry(input_frame, width=15, show="*", bg=THEME["bg_tertiary"], fg=THEME["fg_light"], insertbackground=THEME["fg_light"])
        self.password_entry.grid(row=0, column=5, padx=5)
        
        # Colonne 2 : Boutons
        button_frame = tk.Frame(conn_frame, bg=THEME["bg_secondary"])
        button_frame.pack(side=tk.RIGHT, padx=10)
        
        self.connect_button = tk.Button(button_frame, text="✅ Se connecter", command=self.connect_to_server, 
                                        bg=THEME["success_green"], fg=THEME["fg_light"], font=("Arial", 9, "bold"),
                                        relief=tk.FLAT, padx=15, pady=5)
        self.connect_button.pack(side=tk.LEFT, padx=5)
        
        self.disconnect_button = tk.Button(button_frame, text="❌ Déconnexion", command=self.disconnect_safe,
                                           bg=THEME["error_red"], fg=THEME["fg_light"], font=("Arial", 9, "bold"),
                                           relief=tk.FLAT, padx=15, pady=5, state='disabled')
        self.disconnect_button.pack(side=tk.LEFT, padx=5)

    def create_status_section(self):
        """Crée la section de statut avec indicateurs."""
        status_frame = tk.Frame(self.master, bg=THEME["bg_secondary"], padx=15, pady=12)
        status_frame.pack(fill=tk.X, padx=10, pady=(0, 5))
        
        # Indicateur de connexion
        self.status_label = tk.Label(status_frame, text="🔴 Déconnecté", bg=THEME["bg_secondary"], 
                                     fg=THEME["error_red"], font=("Arial", 12, "bold"))
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Badges de sécurité
        self.security_label = tk.Label(status_frame, text="", bg=THEME["bg_secondary"], 
                                       fg=THEME["success_green"], font=("Arial", 9))
        self.security_label.pack(side=tk.RIGHT)

    def create_history_section(self, parent):
        """Crée la section d'historique des messages."""
        history_frame = tk.Frame(parent, bg=THEME["bg_secondary"])
        history_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        tk.Label(history_frame, text="📋 Historique des Messages", bg=THEME["bg_secondary"], 
                fg=THEME["fg_light"], font=("Arial", 10, "bold")).pack(fill=tk.X, padx=5, pady=5)
        
        # Zone d'historique avec colors
        self.history_text = scrolledtext.ScrolledText(history_frame, state='disabled', wrap=tk.WORD, 
                                                     height=25, font=("Courier", 9),
                                                     bg=THEME["bg_dark"], fg=THEME["fg_light"],
                                                     insertbackground=THEME["fg_light"])
        self.history_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Définir les couleurs des tags
        self.history_text.tag_config("toi", foreground=THEME["accent_blue"], font=("Courier", 9, "bold"))
        self.history_text.tag_config("serveur", foreground=THEME["success_green"], font=("Courier", 9, "bold"))
        self.history_text.tag_config("systeme", foreground=THEME["fg_muted"], font=("Courier", 9, "italic"))
        self.history_text.tag_config("erreur", foreground=THEME["error_red"], font=("Courier", 9, "bold"))
        self.history_text.tag_config("timestamp", foreground=THEME["stat_gold"], font=("Courier", 8))

    def create_stats_panel(self, parent):
        """Crée le panneau de statistiques en temps réel."""
        stats_frame = tk.Frame(parent, bg=THEME["bg_secondary"], width=250)
        stats_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(5, 0))
        stats_frame.pack_propagate(False)
        
        tk.Label(stats_frame, text="📊 STATISTIQUES", bg=THEME["bg_secondary"], 
                fg=THEME["stat_gold"], font=("Arial", 10, "bold")).pack(fill=tk.X, padx=10, pady=(10, 5))
        
        # Durée de connexion
        conn_inner = tk.Frame(stats_frame, bg=THEME["bg_tertiary"])
        conn_inner.pack(fill=tk.X, padx=10, pady=3)
        tk.Label(conn_inner, text="⏱️  Durée :", bg=THEME["bg_tertiary"], fg=THEME["fg_light"], font=("Arial", 8)).pack(side=tk.LEFT)
        self.duration_label = tk.Label(conn_inner, text="00:00:00", bg=THEME["bg_tertiary"], fg=THEME["accent_blue"], font=("Arial", 8, "bold"))
        self.duration_label.pack(side=tk.RIGHT)
        
        # Messages
        msg_inner = tk.Frame(stats_frame, bg=THEME["bg_tertiary"])
        msg_inner.pack(fill=tk.X, padx=10, pady=3)
        tk.Label(msg_inner, text="💬 Messages :", bg=THEME["bg_tertiary"], fg=THEME["fg_light"], font=("Arial", 8)).pack(side=tk.LEFT)
        self.msg_label = tk.Label(msg_inner, text="0 ↑ / 0 ↓", bg=THEME["bg_tertiary"], fg=THEME["accent_blue"], font=("Arial", 8, "bold"))
        self.msg_label.pack(side=tk.RIGHT)
        
        # Données
        data_inner = tk.Frame(stats_frame, bg=THEME["bg_tertiary"])
        data_inner.pack(fill=tk.X, padx=10, pady=3)
        tk.Label(data_inner, text="📦 Données :", bg=THEME["bg_tertiary"], fg=THEME["fg_light"], font=("Arial", 8)).pack(side=tk.LEFT)
        self.data_label = tk.Label(data_inner, text="0 B ↑ / 0 B ↓", bg=THEME["bg_tertiary"], fg=THEME["accent_blue"], font=("Arial", 8, "bold"))
        self.data_label.pack(side=tk.RIGHT)
        
        # Latence
        latency_inner = tk.Frame(stats_frame, bg=THEME["bg_tertiary"])
        latency_inner.pack(fill=tk.X, padx=10, pady=3)
        tk.Label(latency_inner, text="🔄 Latence :", bg=THEME["bg_tertiary"], fg=THEME["fg_light"], font=("Arial", 8)).pack(side=tk.LEFT)
        self.latency_label = tk.Label(latency_inner, text="-- ms", bg=THEME["bg_tertiary"], fg=THEME["accent_blue"], font=("Arial", 8, "bold"))
        self.latency_label.pack(side=tk.RIGHT)
        
        # Séparateur
        tk.Frame(stats_frame, height=1, bg=THEME["bg_secondary"]).pack(fill=tk.X, pady=10)
        
        # SÉCURITÉ
        tk.Label(stats_frame, text="🔐 SÉCURITÉ", bg=THEME["bg_secondary"], 
                fg=THEME["stat_gold"], font=("Arial", 10, "bold")).pack(fill=tk.X, padx=10, pady=(10, 5))
        
        security_items = [
            ("🔑 Clé", "256-bit AES"),
            ("🔒 Mode", "GCM Auth"),
            ("🔐 HMAC", "SHA256"),
            ("⚙️  Dérivation", "PBKDF2 100K"),
            ("🎲 Salt", "Random ✓"),
        ]
        
        for label_text, value in security_items:
            sec_inner = tk.Frame(stats_frame, bg=THEME["bg_tertiary"])
            sec_inner.pack(fill=tk.X, padx=10, pady=2)
            tk.Label(sec_inner, text=label_text, bg=THEME["bg_tertiary"], fg=THEME["fg_light"], font=("Arial", 8)).pack(side=tk.LEFT)
            tk.Label(sec_inner, text=value, bg=THEME["bg_tertiary"], fg=THEME["success_green"], font=("Arial", 8, "bold")).pack(side=tk.RIGHT)

    def create_message_section(self):
        """Crée la section d'envoi de messages."""
        msg_frame = tk.Frame(self.master, bg=THEME["bg_secondary"], padx=10, pady=10)
        msg_frame.pack(fill=tk.X, padx=10, pady=(5, 5))
        
        # Dropdown de messages de démo
        demo_frame = tk.Frame(msg_frame, bg=THEME["bg_secondary"])
        demo_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        tk.Label(demo_frame, text="📝 Messages de démo:", bg=THEME["bg_secondary"], fg=THEME["fg_light"], font=("Arial", 8)).pack(side=tk.LEFT, padx=5)
        
        demo_messages = [
            "Texte simple pour démo",
            "Message avec accents : éàû ç",
            "Emoji test 🔐 🔑 🛡️ 🚀",
            "Données CSV : 1,Alice,alice@example.com",
            "Unicode : 中文 日本語 한국어 العربية",
            "Caractères spéciaux : !@#$%^&*()",
        ]
        
        self.demo_var = tk.StringVar(value="Choisir un message...")
        self.demo_dropdown = tk.OptionMenu(demo_frame, self.demo_var, *demo_messages, command=self.insert_demo_message)
        self.demo_dropdown.config(bg=THEME["bg_tertiary"], fg=THEME["fg_light"], activebackground=THEME["accent_blue"])
        self.demo_dropdown.pack(side=tk.LEFT, padx=5)
        
        # Zone de saisie du message
        input_frame = tk.Frame(msg_frame, bg=THEME["bg_secondary"])
        input_frame.pack(fill=tk.X)
        
        self.msg_entry = tk.Entry(input_frame, bg=THEME["bg_tertiary"], fg=THEME["fg_light"], insertbackground=THEME["fg_light"], font=("Arial", 10))
        self.msg_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.msg_entry.bind("<Return>", self.send_message)
        self.msg_entry.config(state='disabled')
        
        # Bouton envoyer
        self.send_button = tk.Button(input_frame, text="📤 Envoyer", command=self.send_message,
                                     bg=THEME["accent_blue"], fg=THEME["fg_light"], font=("Arial", 9, "bold"),
                                     relief=tk.FLAT, padx=15, state='disabled')
        self.send_button.pack(side=tk.LEFT, padx=5)

    def create_action_buttons(self):
        """Crée les boutons d'action."""
        action_frame = tk.Frame(self.master, bg=THEME["bg_secondary"], padx=10, pady=10)
        action_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        button_style = {"bg": THEME["bg_tertiary"], "fg": THEME["fg_light"], "font": ("Arial", 8, "bold"), "relief": tk.FLAT, "padx": 10, "pady": 5}
        
        tk.Button(action_frame, text="💾 Exporter Historique", command=self.export_history, **button_style).pack(side=tk.LEFT, padx=3)
        tk.Button(action_frame, text="🗑️  Effacer Historique", command=self.clear_history, **button_style).pack(side=tk.LEFT, padx=3)
        tk.Button(action_frame, text="📁 Envoyer un fichier", command=self.send_file, **button_style).pack(side=tk.LEFT, padx=3)
        tk.Button(action_frame, text="🔄 Ping", command=self.ping_server, **button_style).pack(side=tk.LEFT, padx=3)
        tk.Button(action_frame, text="ℹ️  À propos", command=self.show_about, **button_style).pack(side=tk.LEFT, padx=3)

    def get_timestamp(self):
        """Retourne l'heure actuelle au format HH:MM:SS."""
        return datetime.now().strftime("%H:%M:%S")

    def log_message(self, message, sender="Système"):
        """Ajoute un message à l'historique avec timestamp et couleur."""
        timestamp = self.get_timestamp()
        self.history_text.config(state='normal')
        
        self.history_text.insert(tk.END, f"[{timestamp}] ", "timestamp")
        sender_lower = sender.lower()
        tag = sender_lower if sender_lower in ["toi", "serveur", "systeme", "erreur"] else "systeme"
        self.history_text.insert(tk.END, f"{sender}: ", tag)
        self.history_text.insert(tk.END, f"{message}\n")
        
        self.history_text.config(state='disabled')
        self.history_text.see(tk.END)

    def insert_demo_message(self, value):
        """Insère un message de démo dans le champ de texte."""
        if value != "Choisir un message...":
            self.msg_entry.delete(0, tk.END)
            self.msg_entry.insert(0, value)
            self.msg_entry.focus()

    def update_stats(self):
        """Met à jour les statistiques en temps réel."""
        if self.connected and self.start_time:
            # Durée
            elapsed = datetime.now() - self.start_time
            elapsed_str = str(elapsed).split('.')[0]  # HH:MM:SS
            self.duration_label.config(text=elapsed_str)
            
            # Messages et données
            self.msg_label.config(text=f"{self.msg_sent} ↑ / {self.msg_received} ↓")
            
            # Format bytes
            def format_bytes(b):
                for unit in ['B', 'KB', 'MB']:
                    if b < 1024:
                        return f"{b:.1f} {unit}"
                    b /= 1024
                return f"{b:.1f} GB"
            
            self.data_label.config(text=f"{format_bytes(self.bytes_sent)} ↑ / {format_bytes(self.bytes_received)} ↓")
            
            # Latence
            if self.latency_ms > 0:
                self.latency_label.config(text=f"{self.latency_ms} ms")
            
            # Relancer la mise à jour
            self.master.after(1000, self.update_stats)

    def connect_to_server(self):
        """Établit la connexion au serveur VPN."""
        ip = self.ip_entry.get()
        port = self.port_entry.get()
        self.mot_de_passe = self.password_entry.get()

        if not self.mot_de_passe:
            messagebox.showerror("Erreur", "Le mot de passe ne peut pas être vide.")
            return

        try:
            port = int(port)
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((ip, port))
        except (ConnectionRefusedError, OSError) as e:
            messagebox.showerror("Erreur de connexion", f"Impossible de joindre le serveur : {e}")
            self.sock = None
            return
        except ValueError:
            messagebox.showerror("Erreur", "Le port doit être un nombre.")
            return

        # Authentification
        try:
            if not self.authentifier():
                messagebox.showerror("Authentification échouée", "Mot de passe incorrect.")
                self.sock.close()
                self.sock = None
                return
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur d'authentification : {e}")
            self.sock.close()
            self.sock = None
            return

        # Connexion établie
        self.connected = True
        self.start_time = datetime.now()
        self.msg_sent = 0
        self.msg_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        
        self.log_message(f"Connecté à {ip}:{port}", "Système")
        self.status_label.config(text="🟢 Connecté", fg=THEME["success_green"])
        self.security_label.config(text="✅ AES-256-GCM | ✅ HMAC-SHA256 | ✅ Zlib")
        
        self.connect_button.config(state='disabled')
        self.disconnect_button.config(state='normal')
        self.msg_entry.config(state='normal')
        self.send_button.config(state='normal')
        
        # Threads
        self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        self.receive_thread.start()
        
        self.keepalive_thread = threading.Thread(target=self.keepalive, daemon=True)
        self.keepalive_thread.start()
        
        # Mettre à jour les stats
        self.update_stats()

    def authentifier(self) -> bool:
        """Effectue l'authentification HMAC challenge-response."""
        try:
            donnees = recevoir(self.sock)
            msg_type, seq, nonce = deballer(donnees)
            
            if msg_type != TypeMessage.CHALLENGE:
                return False
            
            hmac_reponse = hmac.new(self.mot_de_passe.encode(), nonce, 'sha256').digest()
            envoyer(self.sock, emballer(TypeMessage.AUTH_REQ, hmac_reponse, seq=0))
            
            donnees = recevoir(self.sock)
            msg_type, seq, payload = deballer(donnees)
            
            return msg_type == TypeMessage.AUTH_OK
        
        except Exception as e:
            self.log_message(f"Erreur lors de l'authentification : {e}", "Erreur")
            return False

    def receive_messages(self):
        """Thread de réception des messages."""
        while self.connected and self.sock:
            try:
                donnees = recevoir(self.sock)
                msg_type, seq, payload = deballer(donnees)
                
                if msg_type == TypeMessage.DATA:
                    reponse = dechiffrer(payload, self.mot_de_passe)
                    self.msg_received += 1
                    self.bytes_received += len(reponse.encode())
                    self.log_message(reponse, "Serveur")
                
                elif msg_type == TypeMessage.PONG:
                    self.last_ping_time = time.time()
                
                elif msg_type == TypeMessage.CLOSE:
                    self.log_message("Serveur fermé la connexion", "Système")
                    break
            
            except (ConnectionResetError, OSError):
                break
            except Exception as e:
                self.log_message(f"Erreur : {e}", "Erreur")
                break
        
        if self.connected:
            self.log_message("Connexion perdue avec le serveur.", "Système")
            self.disconnect()

    def keepalive(self):
        """Envoie des PING au serveur."""
        seq = 0
        while self.connected and self.sock:
            time.sleep(30)
            try:
                self.last_ping_time = time.time()
                envoyer(self.sock, emballer(TypeMessage.PING, b'', seq=seq))
                seq += 1
            except OSError:
                break

    def send_message(self, event=None):
        """Envoie un message au serveur."""
        message = self.msg_entry.get()
        if message and self.sock and self.connected:
            try:
                message_chiffre = chiffrer(message, self.mot_de_passe)
                envoyer(self.sock, emballer(TypeMessage.DATA, message_chiffre, seq=0))
                self.msg_sent += 1
                self.bytes_sent += len(message.encode())
                self.log_message(message, "Toi")
                self.msg_entry.delete(0, tk.END)
            except OSError:
                self.log_message("Erreur d'envoi, connexion perdue.", "Erreur")
                self.disconnect()

    def ping_server(self):
        """Teste la latence vers le serveur."""
        if self.connected and self.sock:
            try:
                ping_time = time.time()
                self.last_ping_time = ping_time
                envoyer(self.sock, emballer(TypeMessage.PING, b'', seq=0))
                self.log_message("Ping envoyé...", "Système")
            except OSError:
                self.log_message("Erreur lors du ping", "Erreur")
        else:
            messagebox.showwarning("Non connecté", "Connectez-vous d'abord au serveur.")

    def send_file(self):
        """Envoie un fichier au serveur."""
        if not self.connected:
            messagebox.showwarning("Non connecté", "Connectez-vous d'abord au serveur.")
            return
        
        file_path = filedialog.askopenfilename(title="Sélectionner un fichier à envoyer")
        if file_path:
            try:
                from file_transfer import envoyer_fichier
                if envoyer_fichier(self.sock, file_path, self.mot_de_passe):
                    self.log_message(f"Fichier '{os.path.basename(file_path)}' envoyé avec succès", "Système")
                    self.bytes_sent += os.path.getsize(file_path)
            except Exception as e:
                self.log_message(f"Erreur lors de l'envoi du fichier : {e}", "Erreur")

    def export_history(self):
        """Exporte l'historique en fichier TXT."""
        if self.history_text.get("1.0", tk.END).strip():
            file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Texte", "*.txt"), ("CSV", "*.csv")])
            if file_path:
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(self.history_text.get("1.0", tk.END))
                    messagebox.showinfo("Succès", f"Historique exporté : {file_path}")
                    self.log_message(f"Historique exporté vers {os.path.basename(file_path)}", "Système")
                except Exception as e:
                    messagebox.showerror("Erreur", f"Impossible d'exporter : {e}")
        else:
            messagebox.showwarning("Vide", "L'historique est vide.")

    def clear_history(self):
        """Efface l'historique des messages."""
        if messagebox.askyesno("Confirmation", "Êtes-vous sûr de vouloir effacer l'historique ?"):
            self.history_text.config(state='normal')
            self.history_text.delete("1.0", tk.END)
            self.history_text.config(state='disabled')
            self.log_message("Historique effacé", "Système")

    def show_about(self):
        """Affiche la fenêtre À propos."""
        about_text = """
🔐 CLIENT VPN CHIFFRÉ
Version Éducative v2.0

Protocole : AES-256-GCM + HMAC-SHA256
Dérivation clé : PBKDF2 (100k itérations)
Anti-bruteforce : 3 tentatives max / 60s bannissement

Features:
✅ Chiffrement authentifié
✅ Authentification challenge-response
✅ Compression Zlib
✅ Multi-client sur serveur
✅ Transfert fichiers sécurisé
✅ Keepalive automatique
✅ Interface graphique professionnelle

Créé pour l'éducation à la cybersécurité.
"""
        messagebox.showinfo("À propos", about_text)

    def disconnect(self):
        """Ferme la connexion."""
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
        
        self.status_label.config(text="🔴 Déconnecté", fg=THEME["error_red"])
        self.security_label.config(text="")
        self.connect_button.config(state='normal')
        self.disconnect_button.config(state='disabled')
        self.msg_entry.config(state='disabled')
        self.send_button.config(state='disabled')
        self.log_message("Déconnecté.", "Système")

    def disconnect_safe(self):
        """Déconnexion sécurisée."""
        if self.sock and self.connected:
            try:
                envoyer(self.sock, emballer(TypeMessage.CLOSE, b'', seq=0))
            except:
                pass
            finally:
                self.disconnect()
        else:
            self.disconnect()

    def on_closing(self):
        """Gère la fermeture de la fenêtre."""
        if self.connected:
            self.disconnect_safe()
        self.master.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = VpnClientGUI(root)
    root.mainloop()



if __name__ == "__main__":
    root = tk.Tk()
    app = VpnClientGUI(root)
    root.mainloop()
