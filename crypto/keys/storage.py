"""Development/test key store - NOT for production CA keys.

Keys are written as small JSON envelopes in one directory:

* ``<name>.pub.json`` :: ``{"version": 1, "algorithm": ..., "public_key": b64}``
* ``<name>.key.json`` :: ``{"version": 1, "algorithm": ..., "encrypted": false, "private_key": b64}``
  or, with a passphrase,
  ``{"version": 1, "algorithm": ..., "encrypted": true, "kdf": "PBKDF2-HMAC-SHA256",
  "iterations": n, "salt": b64, "ciphertext": <Fernet token>}``

Production CA key management belongs to the PKI workstream.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from crypto.errors import InvalidKeyError, SerializationError

from .model import KeyPair, PrivateKey, PublicKey

_VERSION = 1
_KDF_ITERATIONS = 600_000
_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError, TypeError):
        raise SerializationError("stored key field is not valid base64") from None


def _fernet(passphrase: str, salt: bytes, iterations: int) -> Fernet:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return Fernet(base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8"))))


class DevKeyStore:
    """Save and load algorithm-tagged keys as JSON files in one directory."""

    def __init__(self, directory: str | os.PathLike) -> None:
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path(self, name: str, suffix: str) -> Path:
        if not _NAME.match(name):
            raise SerializationError(f"invalid key name {name!r}")
        return self._dir / f"{name}.{suffix}.json"

    @staticmethod
    def _read(path: Path) -> dict:
        try:
            obj = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise SerializationError(f"no stored key {path.name!r}") from None
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise SerializationError(f"stored key {path.name!r} is not valid JSON") from None
        if not isinstance(obj, dict) or obj.get("version") != _VERSION or "algorithm" not in obj:
            raise SerializationError(f"stored key {path.name!r} has an unsupported format")
        return obj

    # -- public keys ------------------------------------------------------
    def save_public_key(self, name: str, public_key: PublicKey) -> Path:
        path = self._path(name, "pub")
        payload = {"version": _VERSION, "algorithm": public_key.algorithm, "public_key": _b64(public_key.data)}
        path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        return path

    def load_public_key(self, name: str) -> PublicKey:
        obj = self._read(self._path(name, "pub"))
        return PublicKey(obj["algorithm"], _unb64(obj.get("public_key", "")))

    # -- private keys -----------------------------------------------------
    def save_private_key(self, name: str, private_key: PrivateKey, passphrase: str | None = None) -> Path:
        path = self._path(name, "key")
        payload: dict = {"version": _VERSION, "algorithm": private_key.algorithm}
        if passphrase is None:
            payload.update(encrypted=False, private_key=_b64(private_key.data))
        else:
            salt = os.urandom(16)
            token = _fernet(passphrase, salt, _KDF_ITERATIONS).encrypt(private_key.data)
            payload.update(
                encrypted=True,
                kdf="PBKDF2-HMAC-SHA256",
                iterations=_KDF_ITERATIONS,
                salt=_b64(salt),
                ciphertext=token.decode("ascii"),
            )
        path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        return path

    def load_private_key(self, name: str, passphrase: str | None = None) -> PrivateKey:
        obj = self._read(self._path(name, "key"))
        if not obj.get("encrypted"):
            return PrivateKey(obj["algorithm"], _unb64(obj.get("private_key", "")))
        if passphrase is None:
            raise SerializationError(f"stored key {name!r} is encrypted; a passphrase is required")
        try:
            fernet = _fernet(passphrase, _unb64(obj["salt"]), int(obj["iterations"]))
            data = fernet.decrypt(obj["ciphertext"].encode("ascii"))
        except InvalidToken:
            raise SerializationError(f"cannot decrypt stored key {name!r} (wrong passphrase?)") from None
        except (KeyError, TypeError, ValueError):
            raise SerializationError(f"stored key {name!r} has a malformed encryption envelope") from None
        return PrivateKey(obj["algorithm"], data)

    # -- key pairs --------------------------------------------------------
    def save_keypair(self, name: str, keypair: KeyPair, passphrase: str | None = None) -> tuple[Path, Path]:
        return (
            self.save_private_key(name, keypair.private_key, passphrase),
            self.save_public_key(name, keypair.public_key),
        )

    def load_keypair(self, name: str, passphrase: str | None = None) -> KeyPair:
        private_key = self.load_private_key(name, passphrase)
        public_key = self.load_public_key(name)
        if private_key.algorithm != public_key.algorithm:
            raise InvalidKeyError(
                f"stored key pair {name!r} is inconsistent: "
                f"private={private_key.algorithm!r}, public={public_key.algorithm!r}"
            )
        return KeyPair(private_key.algorithm, private_key, public_key)
