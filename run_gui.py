#!/usr/bin/env python3
# run_gui.py — Launcher pour le client GUI VPN

import tkinter as tk
from client_gui import VpnClientGUI

if __name__ == "__main__":
    root = tk.Tk()
    app = VpnClientGUI(root)
    root.mainloop()
