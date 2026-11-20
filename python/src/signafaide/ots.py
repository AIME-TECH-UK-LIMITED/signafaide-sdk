"""Read an OpenTimestamps ``.ots`` proof (§4, §7 check 11), the same way the Rust core does.

It parses the detached-file format and runs every operation, so each attestation is
paired with the message the proof commits to. A Bitcoin attestation's message is the
block's Merkle root in header byte order; check it against the real block header
(:mod:`signafaide.bitcoin`) before calling the proof confirmed. Proofs are capped at
``MAX_PROOF_BYTES`` bytes and ``MAX_NODES`` operations and attestations in total.
"""

from __future__ import annotations

import hashlib
from typing import Callable, Dict, List, Optional, Tuple

MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
TAG_BITCOIN = bytes.fromhex("0588960d73d71901")
TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
MAX_MSG = 4096
MAX_DEPTH = 256
MAX_PROOF_BYTES = 65_536
MAX_NODES = 1024


class OtsError(ValueError):
    pass


# --- the hash operations ------------------------------------------------------------

_KECCAK_RC = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
]
_KECCAK_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M64 = (1 << 64) - 1


def _rol(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & _M64 if n else x


def keccak256(data: bytes) -> bytes:
    """Keccak-256 (the original padding, as OpenTimestamps uses; not SHA3-256)."""
    rate = 136
    msg = bytearray(data) + b"\x01"
    msg += b"\x00" * (-len(msg) % rate)
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off : off + rate]
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(block[8 * i : 8 * i + 8], "little")
        for rc in _KECCAK_RC:
            c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
            d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
            a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
            b = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _KECCAK_ROT[x][y])
            a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
            a[0][0] ^= rc
    return b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


def _ripemd160_pure(data: bytes) -> bytes:
    def f(j: int, x: int, y: int, z: int) -> int:
        if j < 16:
            return x ^ y ^ z
        if j < 32:
            return (x & y) | (~x & z)
        if j < 48:
            return (x | ~y) ^ z
        if j < 64:
            return (x & z) | (y & ~z)
        return x ^ (y | ~z)

    kl = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    kr = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
    rl = [
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        7,
        4,
        13,
        1,
        10,
        6,
        15,
        3,
        12,
        0,
        9,
        5,
        2,
        14,
        11,
        8,
        3,
        10,
        14,
        4,
        9,
        15,
        8,
        1,
        2,
        7,
        0,
        6,
        13,
        11,
        5,
        12,
        1,
        9,
        11,
        10,
        0,
        8,
        12,
        4,
        13,
        3,
        7,
        15,
        14,
        5,
        6,
        2,
        4,
        0,
        5,
        9,
        7,
        12,
        2,
        10,
        14,
        1,
        3,
        8,
        11,
        6,
        15,
        13,
    ]
    rr = [
        5,
        14,
        7,
        0,
        9,
        2,
        11,
        4,
        13,
        6,
        15,
        8,
        1,
        10,
        3,
        12,
        6,
        11,
        3,
        7,
        0,
        13,
        5,
        10,
        14,
        15,
        8,
        12,
        4,
        9,
        1,
        2,
        15,
        5,
        1,
        3,
        7,
        14,
        6,
        9,
        11,
        8,
        12,
        2,
        10,
        0,
        4,
        13,
        8,
        6,
        4,
        1,
        3,
        11,
        15,
        0,
        5,
        12,
        2,
        13,
        9,
        7,
        10,
        14,
        12,
        15,
        10,
        4,
        1,
        5,
        8,
        7,
        6,
        2,
        13,
        14,
        0,
        3,
        9,
        11,
    ]
    sl = [
        11,
        14,
        15,
        12,
        5,
        8,
        7,
        9,
        11,
        13,
        14,
        15,
        6,
        7,
        9,
        8,
        7,
        6,
        8,
        13,
        11,
        9,
        7,
        15,
        7,
        12,
        15,
        9,
        11,
        7,
        13,
        12,
        11,
        13,
        6,
        7,
        14,
        9,
        13,
        15,
        14,
        8,
        13,
        6,
        5,
        12,
        7,
        5,
        11,
        12,
        14,
        15,
        14,
        15,
        9,
        8,
        9,
        14,
        5,
        6,
        8,
        6,
        5,
        12,
        9,
        15,
        5,
        11,
        6,
        8,
        13,
        12,
        5,
        12,
        13,
        14,
        11,
        8,
        5,
        6,
    ]
    sr = [
        8,
        9,
        9,
        11,
        13,
        15,
        15,
        5,
        7,
        7,
        8,
        11,
        14,
        14,
        12,
        6,
        9,
        13,
        15,
        7,
        12,
        8,
        9,
        11,
        7,
        7,
        12,
        7,
        6,
        15,
        13,
        11,
        9,
        7,
        15,
        11,
        8,
        6,
        6,
        14,
        12,
        13,
        5,
        14,
        13,
        13,
        7,
        5,
        15,
        5,
        8,
        11,
        14,
        14,
        6,
        14,
        6,
        9,
        12,
        9,
        12,
        5,
        15,
        8,
        8,
        5,
        12,
        9,
        12,
        5,
        14,
        6,
        8,
        13,
        6,
        5,
        15,
        13,
        11,
        11,
    ]
    m32 = 0xFFFFFFFF
    rol = lambda x, n: ((x << n) | (x >> (32 - n))) & m32  # noqa: E731
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    msg = bytearray(data) + b"\x80"
    msg += b"\x00" * ((56 - len(msg) % 64) % 64)
    msg += (8 * len(data) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
    for off in range(0, len(msg), 64):
        x = [int.from_bytes(msg[off + 4 * i : off + 4 * i + 4], "little") for i in range(16)]
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            t = rol((al + (f(j, bl, cl, dl) & m32) + x[rl[j]] + kl[j // 16]) & m32, sl[j]) + el & m32
            al, el, dl, cl, bl = el, dl, rol(cl, 10), bl, t
            t = rol((ar + (f(79 - j, br, cr, dr) & m32) + x[rr[j]] + kr[j // 16]) & m32, sr[j]) + er & m32
            ar, er, dr, cr, br = er, dr, rol(cr, 10), br, t
        t = (h[1] + cl + dr) & m32
        h[1] = (h[2] + dl + er) & m32
        h[2] = (h[3] + el + ar) & m32
        h[3] = (h[4] + al + br) & m32
        h[4] = (h[0] + bl + cr) & m32
        h[0] = t
    return b"".join(v.to_bytes(4, "little") for v in h)


def ripemd160(data: bytes) -> bytes:
    try:
        return hashlib.new("ripemd160", data).digest()
    except ValueError:  # OpenSSL 3 without the legacy provider
        return _ripemd160_pure(data)


_UNARY: Dict[int, Callable[[bytes], bytes]] = {
    0x02: lambda m: hashlib.sha1(m).digest(),
    0x03: ripemd160,
    0x08: lambda m: hashlib.sha256(m).digest(),
    0x67: keccak256,
    0xF2: lambda m: m[::-1],
    0xF3: lambda m: m.hex().encode(),
}
_BINARY = {0xF0: lambda m, a: m + a, 0xF1: lambda m, a: a + m}  # append, prepend


# --- parsing --------------------------------------------------------------------


class _Reader:
    def __init__(self, data: bytes):
        self.data, self.pos, self.nodes = data, 0, 0

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise OtsError("ots: unexpected end of proof")
        self.pos += 1
        return self.data[self.pos - 1]

    def take(self, n: int) -> bytes:
        if len(self.data) - self.pos < n:
            raise OtsError("ots: unexpected end of proof")
        self.pos += n
        return self.data[self.pos - n : self.pos]

    def varuint(self) -> int:
        value = 0
        for shift in range(0, 64, 7):
            b = self.byte()
            value |= (b & 0x7F) << shift
            if not b & 0x80:
                return value
        raise OtsError("ots: varuint too long")

    def varbytes(self, limit: int) -> bytes:
        n = self.varuint()
        if n > limit:
            raise OtsError(f"ots: field longer than {limit} bytes")
        return self.take(n)

    def node(self) -> None:
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise OtsError(f"ots: proof has more than {MAX_NODES} operations and attestations")


Attestation = Tuple[str, object, bytes]  # (kind, height | uri | tag hex, message it commits to)


def parse(data: bytes) -> Tuple[bytes, List[Attestation]]:
    """(digest, attestations) of a detached proof; each attestation is
    ``("bitcoin", height, msg)``, ``("pending", uri, msg)`` or ``("unknown", tag, msg)``."""
    if len(data) > MAX_PROOF_BYTES:
        raise OtsError(f"ots: proof is longer than {MAX_PROOF_BYTES} bytes")
    r = _Reader(data)
    if r.take(len(MAGIC)) != MAGIC:
        raise OtsError("ots: not an OpenTimestamps proof (bad magic)")
    if r.varuint() != 1:
        raise OtsError("ots: unsupported proof version")
    if r.byte() != 0x08:
        raise OtsError("ots: only SHA-256 file digests are supported")
    digest = r.take(32)
    found: List[Attestation] = []
    _timestamp(r, digest, found, 0)
    if r.pos != len(data):
        raise OtsError("ots: trailing bytes after timestamp")
    return digest, found


def _timestamp(r: _Reader, msg: bytes, found: list, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise OtsError("ots: proof nested too deeply")
    while True:
        tag = r.byte()
        fork = tag == 0xFF
        if fork:
            tag = r.byte()
        r.node()
        if tag == 0x00:
            kind, value = _attestation(r)
            found.append((kind, value, msg))
        else:
            if tag in _BINARY:
                arg = r.varbytes(MAX_MSG)
                nxt = _BINARY[tag](msg, arg)
            elif tag in _UNARY:
                nxt = _UNARY[tag](msg)
            else:
                raise OtsError(f"ots: unknown operation tag 0x{tag:02x}")
            if len(nxt) > MAX_MSG:
                raise OtsError(f"ots: operation result longer than {MAX_MSG} bytes")
            _timestamp(r, nxt, found, depth + 1)
        if not fork:
            return


def _attestation(r: _Reader) -> Tuple[str, object]:
    tag = r.take(8)
    p = _Reader(r.varbytes(8192))
    if tag == TAG_BITCOIN:
        return "bitcoin", p.varuint()
    if tag == TAG_PENDING:
        uri = p.varbytes(1000)
        if not all(chr(c).isalnum() and c < 128 or c in b"-.:/_" for c in uri):
            raise OtsError("ots: calendar URI has invalid characters")
        return "pending", uri.decode()
    return "unknown", tag.hex()


def status(data: bytes) -> Tuple[bytes, Optional[int]]:
    """(digest, lowest attested Bitcoin height or None while pending). Raises
    OtsError for a malformed proof or one with no attestation at all."""
    digest, found = parse(data)
    heights = [v for k, v, _ in found if k == "bitcoin"]
    if heights:
        return digest, min(heights)  # type: ignore[type-var]
    if any(k == "pending" for k, _, _ in found):
        return digest, None
    raise OtsError("OTS proof has no attestation")


def bitcoin_attestations(data: bytes) -> List[Tuple[int, bytes]]:
    """(height, the 32-byte Merkle root the proof commits to, in header byte order)."""
    out = []
    for kind, height, msg in parse(data)[1]:
        if kind == "bitcoin":
            if len(msg) != 32:
                raise OtsError(f"ots: the timestamp attestation for block {height} is not over a 32-byte Merkle root")
            out.append((int(height), msg))  # type: ignore[call-overload]
    return out
