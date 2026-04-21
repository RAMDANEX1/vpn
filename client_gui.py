# client_gui.py — Client VPN éducatif avec interface graphique (Tkinter)
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from config import SERVEUR_IP, SERVEUR_PORT, TAILLE_BUFFER
from crypto import chiffrer, dechiffrer

class VpnClientGUI:
    def __init__(self, master):
        self.master = master
        master.title("Client VPN Éducatif")
        master.geometry("500x600")

        self.sock = None
        self.mot_de_passe = None

        # --- Widgets de connexion ---
        conn_frame = tk.Frame(master, padx=10, pady=10)
        conn_frame.pack(fill=tk.X)

        tk.Label(conn_frame, text="IP Serveur:").grid(row=0, column=0, sticky=tk.W)
        self.ip_entry = tk.Entry(conn_frame)
        self.ip_entry.grid(row=0, column=1, sticky=tk.EW)
        self.ip_entry.insert(0, SERVEUR_IP)

        tk.Label(conn_frame, text="Port:").grid(row=1, column=0, sticky=tk.W)
        self.port_entry = tk.Entry(conn_frame)
        self.port_entry.grid(row=1, column=1, sticky=tk.EW)
        self.port_entry.insert(0, str(SERVEUR_PORT))

        tk.Label(conn_frame, text="Mot de passe:").grid(row=2, column=0, sticky=tk.W)
        self.password_entry = tk.Entry(conn_frame, show="*")
        self.password_entry.grid(row=2, column=1, sticky=tk.EW)

        self.connect_button = tk.Button(conn_frame, text="Se connecter", command=self.connect_to_server)
        self.connect_button.grid(row=3, column=0, columnspan=2, pady=5)

        # --- Indicateur de statut ---
        self.status_label = tk.Label(master, text="État : Déconnecté", fg="red", padx=10)
        self.status_label.pack(fill=tk.X)

        # --- Zone d'historique des messages ---
        self.history_text = scrolledtext.ScrolledText(master, state='disabled', wrap=tk.WORD, height=20)
        self.history_text.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

        # --- Widgets d'envoi de message ---
        msg_frame = tk.Frame(master, padx=10, pady=5)
        msg_frame.pack(fill=tk.X)

        self.msg_entry = tk.Entry(msg_frame)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.msg_entry.bind("<Return>", self.send_message)
        self.msg_entry.config(state='disabled')

        self.send_button = tk.Button(msg_frame, text="Envoyer", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT, padx=5)
        self.send_button.config(state='disabled')
        
        master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def log_message(self, message, sender="Système"):
        self.history_text.config(state='normal')
        self.history_text.insert(tk.END, f"[{sender}] {message}\n")
        self.history_text.config(state='disabled')
        self.history_text.see(tk.END)

    def connect_to_server(self):
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
        self.sock.send(self.mot_de_passe.encode())
        reponse = self.sock.recv(TAILLE_BUFFER).decode()

        if reponse == "OK":
            self.log_message(f"Connecté à {ip}:{port}")
            self.status_label.config(text="Tunnel Chiffré : AES-256-GCM", fg="green")
            self.connect_button.config(state='disabled')
            self.msg_entry.config(state='normal')
            self.send_button.config(state='normal')
            
            # Démarrer le thread de réception
            self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()
        else:
            messagebox.showerror("Authentification échouée", "Mot de passe incorrect.")
            self.sock.close()
            self.sock = None

    def receive_messages(self):
        while self.sock:
            try:
                reponse_chiffree = self.sock.recv(TAILLE_BUFFER)
                if not reponse_chiffree:
                    break
                reponse = dechiffrer(reponse_chiffree, self.mot_de_passe)
                self.log_message(reponse, "Serveur")
            except (ConnectionResetError, OSError):
                break
            except ValueError:
                self.log_message("Erreur de déchiffrement, le paquet est peut-être corrompu.", "Erreur")
                break
        
        if self.sock: # Si la boucle s'arrête mais que le socket est encore là
            self.log_message("Connexion perdue avec le serveur.")
            self.disconnect()


    def send_message(self, event=None):
        message = self.msg_entry.get()
        if message and self.sock:
            try:
                self.sock.send(chiffrer(message, self.mot_de_passe))
                self.log_message(message, "Toi")
                self.msg_entry.delete(0, tk.END)
                if message.lower() in ("exit", "quit"):
                    self.on_closing()
            except OSError:
                self.log_message("Erreur d'envoi, connexion perdue.")
                self.disconnect()

    def disconnect(self):
        if self.sock:
            self.sock.close()
            self.sock = None
        self.status_label.config(text="État : Déconnecté", fg="red")
        self.connect_button.config(state='normal')
        self.msg_entry.config(state='disabled')
        self.send_button.config(state='disabled')
        self.log_message("Déconnecté.")

    def on_closing(self):
        if self.sock:
            try:
                # Notifier le serveur de la déconnexion
                self.sock.send(chiffrer("EXIT", self.mot_de_passe))
            except OSError:
                pass # Le socket est peut-être déjà fermé
            finally:
                self.disconnect()
        self.master.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = VpnClientGUI(root)
    root.mainloop()
