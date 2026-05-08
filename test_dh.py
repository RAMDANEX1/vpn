#!/usr/bin/env python3
# Test Diffie-Hellman Key Exchange

from core.crypto import dh_generate_key, dh_compute_shared_secret, dh_derive_session_key

print("[TEST] Diffie-Hellman Key Exchange")

# Server génère ses clés
server_private, server_public = dh_generate_key()
print(f"[SERVER] Private: {server_private % (2**64):016x}... (truncated)")
print(f"[SERVER] Public: {server_public % (2**64):016x}...")

# Client génère ses clés
client_private, client_public = dh_generate_key()
print(f"[CLIENT] Private: {client_private % (2**64):016x}... (truncated)")
print(f"[CLIENT] Public: {client_public % (2**64):016x}...")

# Calculer le secret partagé
server_secret = dh_compute_shared_secret(server_private, client_public)
client_secret = dh_compute_shared_secret(client_private, server_public)

print(f"\n[RESULT] Server salt: {server_secret.hex()}")
print(f"[RESULT] Client salt: {client_secret.hex()}")
print(f"[CHECK] Secrets match: {server_secret == client_secret}")

# Dériver les clés de session
password = "test123"
server_key = dh_derive_session_key(server_secret, password)
client_key = dh_derive_session_key(client_secret, password)

print(f"\n[KEY] Server session key: {server_key.hex()}")
print(f"[KEY] Client session key: {client_key.hex()}")
print(f"[CHECK] Session keys match: {server_key == client_key}")

if server_key == client_key:
    print("\n[OK] Diffie-Hellman exchange successful! Each session gets unique key.")
else:
    print("\n[ERROR] Keys don't match!")
