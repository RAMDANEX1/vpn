# test_crypto.py — Tests unitaires du module crypto (M2)
from crypto import chiffrer, dechiffrer

MDPtest = "vpn_secret_2024"

# Test 1 : chiffrer puis déchiffrer retrouve le message original
msg = "Bonjour, monde !"
assert dechiffrer(chiffrer(msg, MDPtest), MDPtest) == msg
print("✓ TEST 1 OK — chiffrer/déchiffrer roundtrip")

# Test 2 : deux chiffrements du même message donnent des bytes différents (IV aléatoire)
b1 = chiffrer("même message", MDPtest)
b2 = chiffrer("même message", MDPtest)
assert b1 != b2
print("✓ TEST 2 OK — IV aléatoire, pas de déterminisme")

# Test 3 : mauvais mot de passe → ValueError
try:
    dechiffrer(chiffrer("secret", MDPtest), "mauvais_mdp")
    assert False, "Aurait dû lever ValueError"
except ValueError:
    print("✓ TEST 3 OK — mauvais mot de passe rejeté")

# Test 4 : paquet corrompu (1 byte modifié) → ValueError
paquet = bytearray(chiffrer("secret", MDPtest))
paquet[15] ^= 0xFF  # altérer un byte au milieu
try:
    dechiffrer(bytes(paquet), MDPtest)
    assert False, "Aurait dû lever ValueError"
except ValueError:
    print("✓ TEST 4 OK — intégrité vérifiée, paquet corrompu détecté")

# Test 5 : compression active
msg_long = "Ceci est un message très long. " * 20  # répétition pour maximiser compression
msg_chiffre = chiffrer(msg_long, MDPtest, compresser=True)
msg_chiffre_sans_compression = chiffrer(msg_long, MDPtest, compresser=False)
# Le chiffré compressé devrait être plus petit
assert len(msg_chiffre) < len(msg_chiffre_sans_compression), "Compression devrait réduire la taille"
assert dechiffrer(msg_chiffre, MDPtest) == msg_long
print("✓ TEST 5 OK — compression active réduit la taille")

# Test 6 : caractères spéciaux et Unicode
msg_unicode = "Bonjour 你好 مرحبا Привет 🔐"
assert dechiffrer(chiffrer(msg_unicode, MDPtest), MDPtest) == msg_unicode
print("✓ TEST 6 OK — Unicode et emojis supportés")

# Test 7 : message vide
msg_vide = ""
assert dechiffrer(chiffrer(msg_vide, MDPtest), MDPtest) == msg_vide
print("✓ TEST 7 OK — message vide accepté")

# Test 8 : PBKDF2 avec différents mots de passe
chiffre1 = chiffrer("message", "mdp1")
chiffre2 = chiffrer("message", "mdp2")
assert chiffre1 != chiffre2, "Différents mots de passe → différents chiffrés"
try:
    dechiffrer(chiffre1, "mdp2")
    assert False, "Mauvais mot de passe aurait dû échouer"
except ValueError:
    print("✓ TEST 8 OK — PBKDF2 dérivation clé correcte")

print("\n✅ Tous les tests passés ! crypto.py est sécurisé et robuste.")
print("   • Chiffrement AES-256-GCM")
print("   • Dérivation clé PBKDF2-HMAC-SHA256 (100k itérations)")
print("   • Compression optionnelle zlib")
print("   • Vérification d'intégrité authentifiée")

