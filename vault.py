"""
vault.py — Passit Encryption Engine
=====================================
AES-256-GCM + PBKDF2-HMAC-SHA256
Master password is never stored on disk.
"""

import os
import json
import base64
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

ITERATIONS = 600_000
SALT_SIZE  = 32
NONCE_SIZE = 12
KEY_SIZE   = 32


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def _encrypt(data: bytes, key: bytes) -> dict:
    nonce = os.urandom(NONCE_SIZE)
    ct    = AESGCM(key).encrypt(nonce, data, None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ct":    base64.b64encode(ct).decode(),
    }


def _decrypt(payload: dict, key: bytes) -> bytes:
    nonce = base64.b64decode(payload["nonce"])
    ct    = base64.b64decode(payload["ct"])
    return AESGCM(key).decrypt(nonce, ct, None)


class Vault:
    """
    Encrypted key-value store.
    Each entry: { name: { secret, category, note } }
    """

    def __init__(self, path: str):
        self._path    = Path(path)
        self._key: Optional[bytes] = None
        self._data: dict = {}

    # ── State ──────────────────────────────────────────────────────────────
    @property
    def exists(self) -> bool:
        return self._path.exists()

    @property
    def unlocked(self) -> bool:
        return self._key is not None

    # ── Setup ──────────────────────────────────────────────────────────────
    def create(self, password: str) -> None:
        """Create a new vault with the given master password."""
        if self.exists:
            raise FileExistsError("Vault already exists.")
        salt      = os.urandom(SALT_SIZE)
        self._key  = _derive_key(password, salt)
        self._data = {}
        self._write(salt)

    def unlock(self, password: str) -> bool:
        """Unlock vault. Returns True on success."""
        if not self.exists:
            return False
        raw  = json.loads(self._path.read_text())
        salt = base64.b64decode(raw["salt"])
        key  = _derive_key(password, salt)
        try:
            plain = _decrypt(raw["payload"], key)
        except InvalidTag:
            return False
        self._key  = key
        self._data = json.loads(plain.decode())
        return True

    def lock(self) -> None:
        self._key  = None
        self._data = {}

    # ── CRUD ───────────────────────────────────────────────────────────────
    def add(self, name: str, secret: str,
            category: str = "general", note: str = "") -> None:
        self._need_key()
        self._data[name] = {
            "secret":   secret,
            "category": category,
            "note":     note,
        }
        self._write_current()

    def get(self, name: str) -> Optional[dict]:
        self._need_key()
        return self._data.get(name)

    def delete(self, name: str) -> bool:
        self._need_key()
        if name not in self._data:
            return False
        del self._data[name]
        self._write_current()
        return True

    def entries(self) -> list[dict]:
        self._need_key()
        return [
            {"name": k, "category": v["category"], "note": v["note"]}
            for k, v in self._data.items()
        ]

    def change_password(self, old: str, new: str) -> bool:
        if not self.unlock(old):
            return False
        salt      = os.urandom(SALT_SIZE)
        self._key  = _derive_key(new, salt)
        self._write(salt)
        return True

    # ── Internal ───────────────────────────────────────────────────────────
    def _need_key(self) -> None:
        if not self.unlocked:
            raise PermissionError("Vault is locked.")

    def _write_current(self) -> None:
        raw  = json.loads(self._path.read_text())
        salt = base64.b64decode(raw["salt"])
        self._write(salt)

    def _write(self, salt: bytes) -> None:
        plain = json.dumps(self._data).encode()
        self._path.write_text(json.dumps({
            "v":       1,
            "salt":    base64.b64encode(salt).decode(),
            "payload": _encrypt(plain, self._key),
        }, indent=2))
