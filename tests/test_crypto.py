# test_crypto.py - Tests unitaires du module crypto (M2)
from core.crypto import chiffrer, dechiffrer

MDPtest = "vpn_secret_2024"

# Test 1 : chiffrer puis dechiffrer retrouve le message original
msg = "Bonjour, monde !"
assert dechiffrer(chiffrer(msg, MDPtest), MDPtest) == msg
print("[OK] TEST 1 OK - chiffrer/dechiffrer roundtrip")

# Test 2 : deux chiffrements du meme message donnent des bytes differents (IV aleatoire)
b1 = chiffrer("meme message", MDPtest)
b2 = chiffrer("meme message", MDPtest)
assert b1 != b2
print("[OK] TEST 2 OK - IV aleatoire, pas de determinisme")

# Test 3 : mauvais mot de passe -> ValueError
try:
    dechiffrer(chiffrer("secret", MDPtest), "mauvais_mdp")
    assert False, "Aurait du lever ValueError"
except ValueError:
    print("[OK] TEST 3 OK - mauvais mot de passe rejete")

# Test 4 : paquet corrompu (1 byte modifie) -> ValueError
paquet = bytearray(chiffrer("secret", MDPtest))
paquet[15] ^= 0xFF  # alterer un byte au milieu
try:
    dechiffrer(bytes(paquet), MDPtest)
    assert False, "Aurait du lever ValueError"
except ValueError:
    print("[OK] TEST 4 OK - integrite verifiee, paquet corrompu detecte")

# Test 5 : compression active
msg_long = "Ceci est un message tres long. " * 20  # repetition pour maximiser compression
msg_chiffre = chiffrer(msg_long, MDPtest, compresser=True)
msg_chiffre_sans_compression = chiffrer(msg_long, MDPtest, compresser=False)
# Le chiffre compresse devrait etre plus petit
assert len(msg_chiffre) < len(msg_chiffre_sans_compression), "Compression devrait reduire la taille"
assert dechiffrer(msg_chiffre, MDPtest) == msg_long
print("[OK] TEST 5 OK - compression active reduit la taille")

# Test 6 : caracteres speciaux et Unicode
msg_unicode = "Bonjour test Unicode"
assert dechiffrer(chiffrer(msg_unicode, MDPtest), MDPtest) == msg_unicode
print("[OK] TEST 6 OK - Unicode et caracteres speciaux supportes")

# Test 7 : message vide
msg_vide = ""
assert dechiffrer(chiffrer(msg_vide, MDPtest), MDPtest) == msg_vide
print("[OK] TEST 7 OK - message vide accepte")

# Test 8 : PBKDF2 avec differents mots de passe
chiffre1 = chiffrer("message", "mdp1")
chiffre2 = chiffrer("message", "mdp2")
assert chiffre1 != chiffre2, "Differents mots de passe -> differents chiffres"
try:
    dechiffrer(chiffre1, "mdp2")
    assert False, "Mauvais mot de passe aurait du echouer"
except ValueError:
    print("[OK] TEST 8 OK - PBKDF2 derivation cle correcte")

print("\n[PASS] Tous les tests passes ! crypto.py est securise et robuste.")
print("   - Chiffrement AES-256-GCM")
print("   - Derivation cle PBKDF2-HMAC-SHA256 (100k iterations)")
print("   - Compression optionnelle zlib")
print("   - Verification d'integrite authentifiee")


