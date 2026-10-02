import base64
import sqlite3
import tempfile
import unittest
from pathlib import Path

from crypto_service import (
    VoteDecryptionError,
    decrypt_vote,
    encrypt_vote,
    generate_rsa_key_pair,
    generate_vote_key,
    load_vote_key,
    unwrap_aes_key,
)


class AesGcmVoteTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.key_path = Path(self.temp_dir.name) / "voting_aes.key"
        self.private_key_path = Path(self.temp_dir.name) / "private.pem"
        self.public_key_path = Path(self.temp_dir.name) / "public.pem"
        self.rsa_passphrase = "test-passphrase-at-least-16"
        generate_vote_key(self.key_path)
        generate_rsa_key_pair(self.private_key_path, self.public_key_path, self.rsa_passphrase)
        self.vote_data = {"candidate_id": 42}
        self.aad = b"election:7"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_encrypt_then_decrypt_recovers_original_vote(self):
        encrypted = encrypt_vote(self.vote_data, self.key_path, self.aad)
        self.assertEqual(decrypt_vote(**encrypted, key_path=self.key_path, associated_data=self.aad), self.vote_data)

    def test_same_vote_twice_uses_a_different_nonce_and_ciphertext(self):
        first = encrypt_vote(self.vote_data, self.key_path, self.aad)
        second = encrypt_vote(self.vote_data, self.key_path, self.aad)
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertNotEqual(first["encrypted_vote"], second["encrypted_vote"])

    def test_modified_ciphertext_fails_authentication(self):
        encrypted = encrypt_vote(self.vote_data, self.key_path, self.aad)
        ciphertext = bytearray(base64.b64decode(encrypted["encrypted_vote"]))
        ciphertext[0] ^= 1
        encrypted["encrypted_vote"] = base64.b64encode(ciphertext).decode("ascii")
        with self.assertRaises(VoteDecryptionError):
            decrypt_vote(**encrypted, key_path=self.key_path, associated_data=self.aad)

    def test_modified_nonce_fails_authentication(self):
        encrypted = encrypt_vote(self.vote_data, self.key_path, self.aad)
        nonce = bytearray(base64.b64decode(encrypted["nonce"]))
        nonce[0] ^= 1
        encrypted["nonce"] = base64.b64encode(nonce).decode("ascii")
        with self.assertRaises(VoteDecryptionError):
            decrypt_vote(**encrypted, key_path=self.key_path, associated_data=self.aad)

    def test_sqlite_encrypted_vote_field_does_not_hold_plaintext_payload(self):
        encrypted = encrypt_vote(self.vote_data, self.key_path, self.aad)
        connection = sqlite3.connect(":memory:")
        connection.execute("CREATE TABLE votes (encrypted_vote TEXT NOT NULL, nonce TEXT NOT NULL)")
        connection.execute(
            "INSERT INTO votes (encrypted_vote, nonce) VALUES (?, ?)",
            (encrypted["encrypted_vote"], encrypted["nonce"]),
        )
        stored_value = connection.execute("SELECT encrypted_vote FROM votes").fetchone()[0]
        self.assertNotEqual(stored_value, '{"candidate_id":42}')
        self.assertNotIn("candidate_id", stored_value)

    def test_rsa_protects_and_recovers_the_aes_key(self):
        encrypted = encrypt_vote(
            self.vote_data, self.key_path, self.aad, rsa_public_key_path=self.public_key_path
        )
        recovered = unwrap_aes_key(
            encrypted["encrypted_aes_key"], self.private_key_path, self.rsa_passphrase
        )
        self.assertEqual(recovered, load_vote_key(self.key_path))

    def test_rsa_protected_aes_key_decrypts_the_vote(self):
        encrypted = encrypt_vote(
            self.vote_data, self.key_path, self.aad, rsa_public_key_path=self.public_key_path
        )
        decrypted = decrypt_vote(
            **encrypted,
            key_path=self.key_path,
            associated_data=self.aad,
            rsa_private_key_path=self.private_key_path,
            rsa_passphrase=self.rsa_passphrase,
        )
        self.assertEqual(decrypted, self.vote_data)

    def test_modified_rsa_protected_aes_key_cannot_be_recovered(self):
        encrypted = encrypt_vote(
            self.vote_data, self.key_path, self.aad, rsa_public_key_path=self.public_key_path
        )
        wrapped = bytearray(base64.b64decode(encrypted["encrypted_aes_key"]))
        wrapped[0] ^= 1
        encrypted["encrypted_aes_key"] = base64.b64encode(wrapped).decode("ascii")
        with self.assertRaises(VoteDecryptionError):
            decrypt_vote(
                **encrypted,
                key_path=self.key_path,
                associated_data=self.aad,
                rsa_private_key_path=self.private_key_path,
                rsa_passphrase=self.rsa_passphrase,
            )


if __name__ == "__main__":
    unittest.main()
