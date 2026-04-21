# test_crypto.py — Tests unitaires du module crypto (M2)
from crypto import chiffrer, dechiffrer

MDPtest = "vpn_secret_2024"

# Test 1 : chiffrer puis déchiffrer retrouve le message original
msg = "Bonjour, monde !"
assert dechiffrer(chiffrer(msg, MDPtest), MDPtest) == msg
print("TEST 1 OK — chiffrer/déchiffrer roundtrip")

# Test 2 : deux chiffrements du même message donnent des bytes différents (IV aléatoire)
b1 = chiffrer("même message", MDPtest)
b2 = chiffrer("même message", MDPtest)
assert b1 != b2
print("TEST 2 OK — IV aléatoire, pas de déterminisme")

# Test 3 : mauvais mot de passe → ValueError
try:
    dechiffrer(chiffrer("secret", MDPtest), "mauvais_mdp")
    assert False, "Aurait dû lever ValueError"
except ValueError:
    print("TEST 3 OK — mauvais mot de passe rejeté")

# Test 4 : paquet corrompu (1 byte modifié) → ValueError
paquet = bytearray(chiffrer("secret", MDPtest))
paquet[15] ^= 0xFF  # altérer un byte au milieu
try:
    dechiffrer(bytes(paquet), MDPtest)
    assert False, "Aurait dû lever ValueError"
except ValueError:
    print("TEST 4 OK — intégrité vérifiée, paquet corrompu détecté")

print()
print("Tous les tests passés ! crypto.py est prêt.")
