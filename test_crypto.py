import unittest
from crypto import chiffrer, dechiffrer


class TestCrypto(unittest.TestCase):
    def test_chiffrement_dechiffrement(self) -> None:
        cle = "test-key"
        message = "Bonjour mini-vpn"
        token = chiffrer(message, cle)
        resultat = dechiffrer(token, cle)
        self.assertEqual(resultat, message)

    def test_cles_differentes(self) -> None:
        token = chiffrer("secret", "cle-A")
        with self.assertRaises(ValueError):
            dechiffrer(token, "cle-B")


if __name__ == "__main__":
    unittest.main()
