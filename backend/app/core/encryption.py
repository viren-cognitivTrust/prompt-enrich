from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import get_settings


settings = get_settings()


class KeyProvider:
    """
    Abstract key provider. In production, implement a provider that fetches keys
    from a cloud KMS or secret manager instead of environment variables.
    """

    def get_key(self, key_id: str) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError


class LocalEnvKeyProvider(KeyProvider):
    """
    Local-only key provider.
    Expects a 32-byte (256-bit) key in hex/base64 form in environment variables.
    DO NOT USE THIS IN PRODUCTION.
    """

    def get_key(self, key_id: str) -> bytes:
        raw = os.getenv("PII_ENCRYPTION_KEY")
        if not raw:
            raise RuntimeError(
                "PII_ENCRYPTION_KEY not set. For production, integrate a KMS/secret manager."
            )
        try:
            # Allow hex or base64; here we treat as hex for simplicity.
            return bytes.fromhex(raw)
        except ValueError as exc:  # pragma: no cover - defensive
            raise RuntimeError("PII_ENCRYPTION_KEY must be a hex-encoded 32-byte key") from exc


_key_provider: KeyProvider = LocalEnvKeyProvider()


def set_key_provider(provider: KeyProvider) -> None:
    global _key_provider
    _key_provider = provider


@dataclass
class EncryptedValue:
    key_id: str
    nonce: bytes
    ciphertext: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedValue":
        # key_id is not embedded; stored separately in DB.
        raise NotImplementedError("Use explicit fields for EncryptedValue")


def encrypt_pii(plaintext: str) -> Tuple[str, bytes, bytes]:
    """
    Encrypt PII using AES-256-GCM.
    Returns (key_id, nonce, ciphertext).
    """
    key_id = settings.PII_ENCRYPTION_KEY_ID
    key = _key_provider.get_key(key_id)
    if len(key) != 32:
        raise RuntimeError("PII encryption key must be 32 bytes (AES-256)")

    aesgcm = AESGCM(key)
    # 96-bit nonce recommended for GCM
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return key_id, nonce, ciphertext


def decrypt_pii(key_id: str, nonce: bytes, ciphertext: bytes) -> str:
    key = _key_provider.get_key(key_id)
    if len(key) != 32:
        raise RuntimeError("PII encryption key must be 32 bytes (AES-256)")
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


