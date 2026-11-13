"""Bitcoin block headers for §7 check 11, from an Esplora-style explorer API.

``GET {base}/block-height/{h}`` gives the block hash; ``GET {base}/block/{hash}/header`` gives
the raw 80-byte header (hex). The header is trusted only when it hashes to that block hash and
meets its own proof of work (:func:`check_header`). mempool.space and blockstream.info serve
this API. An explorer over plain http is never asked: anyone on the path could answer.
"""

from __future__ import annotations

import hashlib
import re
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, Iterable, Optional, Tuple, Union

from ._version import __version__

DEFAULT_URL = "https://mempool.space/api"
_HEX64 = re.compile(r"\A[0-9a-fA-F]{64}\Z")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # an explorer answer is never a redirect
        return None


def _get(url: str, timeout: float) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": f"signafaide-python/{__version__}", "Accept": "*/*"})
    with urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout) as r:
        return r.read(1 << 20).decode()


#: Why a plain-http explorer is not asked.
PLAIN_HTTP_EXPLORER = "the explorer URL uses plain http, which anyone on the network path can alter; use https"


def target(bits: int) -> Optional[int]:
    """The target of a compact ``nBits``; None when it is negative, zero or overflows."""
    exponent, mantissa = bits >> 24, bits & 0x7FFFFF
    if bits & 0x800000 or mantissa == 0:
        return None
    t = mantissa << (8 * (exponent - 3)) if exponent >= 3 else mantissa >> (8 * (3 - exponent))
    return t if 0 < t < 1 << 256 else None


def check_header(block_hash: str, header_hex: str) -> bytes:
    """The Merkle root (header byte order) of a header that hashes to ``block_hash`` (display hex)
    and meets its own proof of work. Raises ValueError saying why the header is not trusted."""
    try:
        header = bytes.fromhex(header_hex.strip())
    except (ValueError, AttributeError):
        raise ValueError("the block header is not hex") from None
    if len(header) != 80:
        raise ValueError(f"the block header is {len(header)} bytes, not 80")
    block_id = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1]
    if block_id.hex() != str(block_hash).strip().lower():
        raise ValueError(f"the block header does not hash to block {block_hash}")
    bits = int.from_bytes(header[72:76], "little")
    t = target(bits)
    if t is None:
        raise ValueError(f"the block header's nBits {bits:#010x} is not a valid target")
    if int.from_bytes(block_id, "big") > t:
        raise ValueError(f"block {block_hash} does not meet the proof of work its header claims")
    return header[36:68]


def block_header(base: str, height: int, timeout: float = 15.0) -> Dict[str, str]:
    """``{hash, header}`` of block ``height`` as the explorer serves them. Raises ValueError."""
    base = base.rstrip("/")
    try:
        h = _get(f"{base}/block-height/{height}", timeout).strip().lower()
        if not _HEX64.match(h):
            raise ValueError(f"no block at height {height}")
        header = _get(f"{base}/block/{h}/header", timeout).strip().lower()
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise ValueError(f"{base}: {getattr(e, 'reason', e)}") from None
    return {"hash": h, "header": header}


def lookup(base: str, heights: Iterable[int]) -> Dict[int, Tuple[bool, Any]]:
    """height -> (True, {hash, header}) or (False, why it could not be fetched). A plain-http
    explorer is not asked: every height then says why (the check shows NOT CHECKED)."""
    out: Dict[int, Tuple[bool, Any]] = {}
    plain = base.startswith("http://")
    if plain:
        print(f"WARNING: --timestamp-check {base} uses plain http://, which anyone on the network path can alter: public timestamps are not checked; use https://", file=sys.stderr)
    for h in heights:
        if plain:
            out[h] = (False, PLAIN_HTTP_EXPLORER)
            continue
        try:
            out[h] = (True, block_header(base, h))
        except ValueError as e:
            out[h] = (False, str(e))
    return out


def roots_from_vector(m: Dict[str, Union[str, dict]]) -> Dict[int, Tuple[bool, Any]]:
    """The ``bitcoin`` object of a test vector: height -> {hash, header}."""
    return {int(h): (True, r) for h, r in m.items() if isinstance(r, dict)}
