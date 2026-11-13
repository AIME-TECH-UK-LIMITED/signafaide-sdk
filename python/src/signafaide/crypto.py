"""Hashes, domain-separated Ed25519 and RFC 6962 Merkle proofs (SPEC §1, §3.2)."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from typing import Any, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .jcs import canonicalize

DOMAINS = ("record", "batch", "head", "anchor", "register", "rotate", "agent_key", "export", "draft")
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
SALT_RE = re.compile(r"\A[0-9a-f]{32}\Z")
_B64URL = re.compile(r"\A[A-Za-z0-9_-]*\Z")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_json(value: Any) -> str:
    """sha256(JCS(value)) as 64 lowercase hex."""
    return sha256_hex(canonicalize(value))


def new_salt() -> str:
    """A fresh content salt (SPEC §2.1): 16 random bytes as 32 lowercase hex."""
    return secrets.token_hex(16)


def content_hash(content: Any, salt: str) -> str:
    """sha256(salt || JCS(content)) as 64 lowercase hex (SPEC §2.1); content is a JSON object."""
    if not isinstance(content, dict):
        raise ValueError("content must be a JSON object")
    if not isinstance(salt, str) or not SALT_RE.match(salt):
        raise ValueError("salt must be 32 lowercase hex characters (16 bytes)")
    return sha256_hex(bytes.fromhex(salt) + canonicalize(content))


def check_content(content: Any, salt: Any, expected: str) -> "str | None":
    """The §2.3 content rule: ``content`` and ``salt`` together or not at all. Returns None when
    they match ``expected`` (or are both absent); raises ValueError when they cannot be checked;
    returns the actual hash on a mismatch."""
    if content is None and salt is None:
        return None
    if salt is None:
        raise ValueError("content is present without its salt")
    if content is None:
        raise ValueError("salt is present without content")
    h = content_hash(content, salt)
    return None if h == expected else h


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    if not isinstance(s, str) or not _B64URL.match(s) or len(s) % 4 == 1:
        raise ValueError("not base64url without padding")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def key_id(public_key: bytes) -> str:
    """First 16 hex characters of SHA-256 of the raw 32-byte public key."""
    return sha256_hex(public_key)[:16]


def signed_message(domain: str, hash_hex: str) -> bytes:
    if domain not in DOMAINS:
        raise ValueError(f"unknown signature domain {domain!r}")
    if not HEX64.match(hash_hex or ""):
        raise ValueError("hash must be 64 lowercase hex characters")
    return f"signafaide/v1/{domain}\n".encode() + bytes.fromhex(hash_hex)


class SigningKey:
    """An Ed25519 private key. Only ``sign`` touches the private half."""

    def __init__(self, seed: bytes):
        if len(seed) != 32:
            raise ValueError("an Ed25519 seed is 32 bytes")
        self._sk = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key = self._sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = key_id(self.public_key)

    @classmethod
    def generate(cls) -> "SigningKey":
        sk = Ed25519PrivateKey.generate()
        return cls(sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))

    def seed(self) -> bytes:
        return self._sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())

    def sign(self, domain: str, hash_hex: str) -> str:
        """base64url Ed25519 signature over ``signafaide/v1/<domain>\\n`` + raw hash."""
        return b64url(self._sk.sign(signed_message(domain, hash_hex)))


def verify_sig(public_key_b64: str, domain: str, hash_hex: str, sig_b64: str) -> bool:
    try:
        pk = b64url_decode(public_key_b64)
        sig = b64url_decode(sig_b64)
        if len(pk) != 32 or len(sig) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, signed_message(domain, hash_hex))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# --- RFC 6962 Merkle tree -------------------------------------------------------


def leaf_hash(hash_hex: str) -> bytes:
    return hashlib.sha256(b"\x00" + bytes.fromhex(hash_hex)).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(hashes: Sequence[str]) -> str:
    """Root of the RFC 6962 tree over *hashes* (record or batch hashes, hex)."""
    if not hashes:
        raise ValueError("a Merkle tree needs at least one leaf")
    return _root([leaf_hash(h) for h in hashes]).hex()


def _root(leaves: list) -> bytes:
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return _node(_root(leaves[:k]), _root(leaves[k:]))


def _split(n: int) -> int:
    """Largest power of two strictly less than n."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def audit_path(hashes: Sequence[str], index: int) -> list:
    """The audit path for leaf *index*, from the leaf upward (hex)."""
    leaves = [leaf_hash(h) for h in hashes]
    path: list = []

    def walk(lo: int, hi: int, i: int) -> None:
        if hi - lo == 1:
            return
        k = _split(hi - lo)
        if i < lo + k:
            walk(lo, lo + k, i)
            path.append(_root(leaves[lo + k : hi]).hex())
        else:
            walk(lo + k, hi, i)
            path.append(_root(leaves[lo : lo + k]).hex())

    if not 0 <= index < len(leaves):
        raise ValueError("index out of range")
    walk(0, len(leaves), index)
    return path


def verify_inclusion(hash_hex: str, index: int, size: int, path: Sequence[str], root_hex: str) -> bool:
    """RFC 9162 §2.1.3.2 inclusion check of *hash_hex* at *index* in a tree of *size*."""
    try:
        if not (isinstance(index, int) and isinstance(size, int) and 0 <= index < size):
            return False
        fn, sn = index, size - 1
        r = leaf_hash(hash_hex)
        for p_hex in path:
            p = bytes.fromhex(p_hex)
            if len(p) != 32 or sn == 0:
                return False
            if fn & 1 or fn == sn:
                r = _node(p, r)
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
            else:
                r = _node(r, p)
            fn >>= 1
            sn >>= 1
        return sn == 0 and r.hex() == root_hex
    except (ValueError, TypeError):
        return False

