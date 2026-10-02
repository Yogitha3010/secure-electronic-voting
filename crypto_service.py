import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption


class VoteEncryptionError(RuntimeError):
    """Raised when the locally protected AES voting key cannot be used."""


class VoteDecryptionError(RuntimeError):
    """Raised when a stored ballot cannot be authenticated and decrypted."""


def generate_vote_key(key_path):
    """Create a one-time AES-256 key file without displaying the secret."""
    path = Path(key_path)
    if path.exists():
        raise FileExistsError("AES voting key already exists and will not be overwritten.")
    path.parent.mkdir(parents=True, exist_ok=True)
    key = AESGCM.generate_key(bit_length=256)
    path.write_bytes(key)
    if os.name != "nt":
        os.chmod(path, 0o600)


def load_vote_key(key_path):
    """Load the persistent 32-byte AES-256 key from its protected local file."""
    try:
        key = Path(key_path).read_bytes()
    except OSError as error:
        raise VoteEncryptionError("AES voting key is unavailable.") from error
    if len(key) != 32:
        raise VoteEncryptionError("AES voting key has an invalid length.")
    return key


def generate_rsa_key_pair(private_key_path, public_key_path, passphrase):
    """Generate a 3072-bit RSA pair; persist only an encrypted private PEM."""
    private_path, public_path = Path(private_key_path), Path(public_key_path)
    if private_path.exists() or public_path.exists():
        raise FileExistsError("RSA key files already exist and will not be overwritten.")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_path.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        BestAvailableEncryption(passphrase.encode("utf-8")),
    ))
    public_path.write_bytes(private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    if os.name != "nt":
        os.chmod(private_path, 0o600)


def load_rsa_private_key(private_key_path, passphrase):
    if not passphrase:
        raise VoteEncryptionError("RSA private-key passphrase is unavailable.")
    try:
        return serialization.load_pem_private_key(
            Path(private_key_path).read_bytes(), password=passphrase.encode("utf-8")
        )
    except (OSError, ValueError, TypeError) as error:
        raise VoteEncryptionError("RSA private key is unavailable or invalid.") from error


def wrap_aes_key(aes_key, public_key_path):
    try:
        public_key = serialization.load_pem_public_key(Path(public_key_path).read_bytes())
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Not an RSA public key")
        return base64.b64encode(public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )).decode("ascii")
    except (OSError, ValueError, TypeError) as error:
        raise VoteEncryptionError("RSA public key is unavailable or invalid.") from error


def unwrap_aes_key(encrypted_aes_key, private_key_path, passphrase):
    try:
        return load_rsa_private_key(private_key_path, passphrase).decrypt(
            base64.b64decode(encrypted_aes_key, validate=True),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except (ValueError, TypeError) as error:
        raise VoteDecryptionError("Protected AES key could not be recovered.") from error


def encrypt_vote(vote_data, key_path, associated_data=None, rsa_public_key_path=None):
    """AES-GCM encrypt JSON vote data and Base64 encode fields for SQLite storage."""
    key = load_vote_key(key_path)
    payload = json.dumps(vote_data, separators=(",", ":")).encode("utf-8")
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, payload, associated_data)
    encrypted = {
        "encrypted_vote": base64.b64encode(ciphertext).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
    }
    if rsa_public_key_path:
        encrypted["encrypted_aes_key"] = wrap_aes_key(key, rsa_public_key_path)
    return encrypted


def decrypt_vote(
    encrypted_vote,
    nonce,
    key_path,
    associated_data=None,
    encrypted_aes_key=None,
    rsa_private_key_path=None,
    rsa_passphrase=None,
):
    """Base64 decode and AES-GCM decrypt a ballot, rejecting modified data safely."""
    try:
        ciphertext = base64.b64decode(encrypted_vote, validate=True)
        nonce_bytes = base64.b64decode(nonce, validate=True)
        key = (
            unwrap_aes_key(encrypted_aes_key, rsa_private_key_path, rsa_passphrase)
            if encrypted_aes_key else load_vote_key(key_path)
        )
        payload = AESGCM(key).decrypt(nonce_bytes, ciphertext, associated_data)
        return json.loads(payload.decode("utf-8"))
    except (InvalidTag, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VoteDecryptionError("Encrypted ballot could not be authenticated.") from error
