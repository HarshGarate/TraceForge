"""Passphrase-protected case files.

Format: a JSON envelope holding the scrypt parameters, a random salt and nonce, and the AES-256-GCM ciphertext.
The envelope header is bound to the ciphertext as additional authenticated data, so changing any parameter makes
decryption fail. Wrong passphrases and tampering are indistinguishable by design (both raise CaseCryptoError).
"""
from __future__ import annotations

import base64
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = "traceforge-case-encrypted"
MIN_PASSPHRASE = 10
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1
MAX_SCRYPT_N = 2**17          # refuse files that ask for absurd work/memory on import


class CaseCryptoError(ValueError):
    """Encryption or decryption failed (bad passphrase, damaged or tampered file, unsupported parameters)."""


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _key(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode("utf-8"))


def _aad(header: dict) -> bytes:
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def is_encrypted_case(data: bytes | str) -> bool:
    try:
        obj = json.loads(data)
    except (ValueError, TypeError):
        return False
    return isinstance(obj, dict) and obj.get("format") == MAGIC


def encrypt_case(plaintext: bytes, passphrase: str) -> str:
    if len(passphrase) < MIN_PASSPHRASE:
        raise CaseCryptoError(f"Use a passphrase of at least {MIN_PASSPHRASE} characters.")
    salt, nonce = os.urandom(16), os.urandom(12)
    header = {"format": MAGIC, "version": 1, "kdf": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
              "cipher": "AES-256-GCM", "salt": _b64(salt), "nonce": _b64(nonce)}
    ct = AESGCM(_key(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)).encrypt(nonce, plaintext, _aad(header))
    return json.dumps({**header, "ciphertext": _b64(ct)}, indent=2)


def decrypt_case(blob: bytes | str, passphrase: str) -> bytes:
    try:
        env = json.loads(blob)
        if env.get("format") != MAGIC or env.get("kdf") != "scrypt" or env.get("cipher") != "AES-256-GCM" or env.get("version") != 1:
            raise CaseCryptoError("This is not a supported TraceForge encrypted case file.")
        n, r, p = int(env["n"]), int(env["r"]), int(env["p"])
        if not (2**10 <= n <= MAX_SCRYPT_N) or n & (n - 1) or not (1 <= r <= 16) or not (1 <= p <= 4):
            raise CaseCryptoError("The encrypted case file uses unsupported key-derivation settings.")
        salt, nonce, ct = (base64.b64decode(env[k], validate=True) for k in ("salt", "nonce", "ciphertext"))
        header = {k: v for k, v in env.items() if k != "ciphertext"}
        return AESGCM(_key(passphrase, salt, n, r, p)).decrypt(nonce, ct, _aad(header))
    except CaseCryptoError:
        raise
    except InvalidTag as exc:
        raise CaseCryptoError("Wrong passphrase, or the file was changed after it was encrypted.") from exc
    except (ValueError, KeyError, TypeError) as exc:
        raise CaseCryptoError("The encrypted case file is damaged.") from exc
