#!/usr/bin/env python
# test_client.py - Test automatisé du client VPN
import subprocess
import time

# Envoyer le mot de passe et un message
input_text = "test123\nhello world\nexit\n"

# Lancer le client
proc = subprocess.Popen(
    ["python", "client.py"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    env={"VPN_PASSWORD": "test123"}
)

stdout, stderr = proc.communicate(input=input_text, timeout=15)

print("=== STDOUT ===")
print(stdout)
print("\n=== STDERR ===")
print(stderr)
print("\n=== EXIT CODE ===")
print(proc.returncode)
