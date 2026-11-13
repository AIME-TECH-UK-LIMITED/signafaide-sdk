"""drand quicknet BLS verification (§7 check 9), with the optional ``signafaide[bls]`` extra.

Quicknet is ``bls-unchained-g1-rfc9380``: the signature is a G1 point over
``sha256(round as 8 big-endian bytes)``, the public key a G2 point. Pure Python
(``py_ecc``), so it takes about a second per round: fine for verifying, never on
the recording path.
"""

from __future__ import annotations

import hashlib
from typing import Callable, Optional

QUICKNET_PUBLIC_KEY = (
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
)
DST = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"


def load_verifier() -> Optional[Callable[[dict], bool]]:
    """A ``beacon -> bool`` verifier, or None when ``py_ecc`` is not installed."""
    try:
        from py_ecc.bls.hash_to_curve import hash_to_G1
        from py_ecc.bls.point_compression import decompress_G1, decompress_G2
        from py_ecc.optimized_bls12_381 import FQ12, G2, curve_order, final_exponentiate, is_inf, multiply, neg, pairing
    except ImportError:
        return None

    pk_bytes = bytes.fromhex(QUICKNET_PUBLIC_KEY)
    pk = decompress_G2((int.from_bytes(pk_bytes[:48], "big"), int.from_bytes(pk_bytes[48:], "big")))

    def verify(beacon: dict) -> bool:
        try:
            sig = decompress_G1(int.from_bytes(bytes.fromhex(beacon["signature"]), "big"))
            if is_inf(sig) or not is_inf(multiply(sig, curve_order)):
                return False
            msg = hashlib.sha256(int(beacon["round"]).to_bytes(8, "big")).digest()
            h = hash_to_G1(msg, DST, hashlib.sha256)
            # e(sig, g2) == e(H(m), pk)  <=>  e(sig, g2) * e(H(m), -pk) == 1
            product = pairing(G2, sig, final_exponentiate=False) * pairing(neg(pk), h, final_exponentiate=False)
            return final_exponentiate(product) == FQ12.one()
        except (ValueError, KeyError, TypeError, AssertionError):
            return False

    return verify
