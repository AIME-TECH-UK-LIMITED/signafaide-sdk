"""What the ``secret`` and ``hidden_instruction`` checks read inside a string (SPEC §8): the text
normalised before matching, encoded text decoded (bounded), crypto wallet keys, seed phrases,
wallet addresses and card numbers, and the instruction patterns. Pure functions, no I/O. The
TypeScript SDK has the same functions in ``src/scan.ts``; ``vectors.json`` ``checks.local_checks``
holds the cases both reproduce."""

from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import json
import math
import re
import unicodedata
from typing import Any, List, Optional, Sequence, Tuple

from ._bip39 import BIP39_ENGLISH
from ._confusables import INSTRUCTION_CONFUSABLES

# --- normalisation (§8) --------------------------------------------------------------------

#: Characters removed after NFKC before matching: invisible format characters, variation
#: selectors, fillers and tag characters (§8 normalisation).
REMOVED = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5),
    (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164),
    (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)
_REMOVED_RE = re.compile("[" + "".join(re.escape(chr(a)) + ("" if a == b else "-" + re.escape(chr(b))) for a, b in REMOVED) + "]")
#: Look-alike letters (§8 normalisation): Cyrillic and Greek letters that read as a Latin letter,
#: mapped to it after NFKC (fullwidth forms are already NFKC). Bounded on purpose: only letters a
#: reader takes for a Latin one in a common typeface, so ordinary Russian and Greek words are
#: left alone by every other check, and the table is part of the specification.
CONFUSABLES = (
    (0x037F, "J"),
    (0x0391, "A"),
    (0x0392, "B"),
    (0x0395, "E"),
    (0x0396, "Z"),
    (0x0397, "H"),
    (0x0399, "I"),
    (0x039A, "K"),
    (0x039C, "M"),
    (0x039D, "N"),
    (0x039F, "O"),
    (0x03A1, "P"),
    (0x03A4, "T"),
    (0x03A5, "Y"),
    (0x03A7, "X"),
    (0x03B1, "a"),
    (0x03B9, "i"),
    (0x03BA, "k"),
    (0x03BD, "v"),
    (0x03BF, "o"),
    (0x03C1, "p"),
    (0x03C5, "u"),
    (0x03C7, "x"),
    (0x03F3, "j"),
    (0x0405, "S"),
    (0x0406, "I"),
    (0x0408, "J"),
    (0x0410, "A"),
    (0x0412, "B"),
    (0x0415, "E"),
    (0x041A, "K"),
    (0x041C, "M"),
    (0x041D, "H"),
    (0x041E, "O"),
    (0x0420, "P"),
    (0x0421, "C"),
    (0x0422, "T"),
    (0x0423, "Y"),
    (0x0425, "X"),
    (0x0430, "a"),
    (0x0435, "e"),
    (0x043E, "o"),
    (0x0440, "p"),
    (0x0441, "c"),
    (0x0443, "y"),
    (0x0445, "x"),
    (0x0455, "s"),
    (0x0456, "i"),
    (0x0458, "j"),
    (0x0475, "v"),
    (0x04BB, "h"),
    (0x04C0, "I"),
    (0x04CF, "l"),
    (0x0501, "d"),
    (0x051B, "q"),
    (0x051D, "w"),
)
_CONFUSABLE_MAP = {c: l for c, l in CONFUSABLES}
_PLAIN = re.compile(r"[\t\n\r\x20-\x7e]*\Z")


def normalise(s: str) -> str:
    """A string as the checks read it (§8): NFKC, then the ``REMOVED`` characters taken out, then
    each ``CONFUSABLES`` letter replaced by the Latin letter it looks like."""
    if s.isascii():  # NFKC, the removed characters and the table change no ASCII text
        return s
    return _REMOVED_RE.sub("", unicodedata.normalize("NFKC", s)).translate(_CONFUSABLE_MAP)


class _InstructionMap(dict):
    """``str.translate`` table for instruction text: a nonspacing mark (Mn) to nothing, an
    ``INSTRUCTION_CONFUSABLES`` letter to its Latin letter, any other character to itself; filled
    as characters are seen (at most 65,536 kept)."""

    def __missing__(self, c: int):
        v = None if unicodedata.category(chr(c)) == "Mn" else _CONFUSABLE_LETTERS.get(c, c)
        if len(self) < 65536:
            self[c] = v
        return v


_CONFUSABLE_LETTERS = {c: l for c, l in INSTRUCTION_CONFUSABLES}
_INSTRUCTION_MAP = _InstructionMap()


_ASCII_SPACE = re.compile(r"[\t\n\r ]+")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def instruction_text(s: str) -> str:
    """The text the instruction patterns read (§8 hidden_instruction): normalised, then NFKD with
    the nonspacing marks (Mn) taken out, then each ``INSTRUCTION_CONFUSABLES`` letter replaced by
    its Latin letter, ASCII letters lowercased, each run of whitespace one space. Only instruction
    matching reads the marks and that table; the secret and address checks read ``normalise``."""
    t = normalise(s)
    if not t.isascii():  # NFKD changes no ASCII text
        t = unicodedata.normalize("NFKD", t)
        if not t.isascii():
            t = t.translate(_INSTRUCTION_MAP)
    if t.isascii() and not _CONTROL.search(t):  # plain ASCII: lower() changes only A to Z
        t = t.lower()
        return _ASCII_SPACE.sub(" ", t) if ("  " in t or "\t" in t or "\n" in t or "\r" in t) else t
    t = re.sub(r"[A-Z]+", lambda m: m.group(0).lower(), t)
    return re.sub(r"\s+", " ", t)


# --- decoding (§8 secret) ------------------------------------------------------------------

#: At most this many decodings in a row (base64 of hex of a secret is two).
DECODE_DEPTH = 3
_HEX_CHARS = "0123456789ABCDEFabcdef"
_B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_HEX_ONLY = re.compile(r"[0-9A-Fa-f]+\Z")


def _kind(chars: str) -> Tuple[dict, "re.Pattern[str]"]:
    table = str.maketrans({chr(i): (chr(i) if chr(i) in chars else " ") for i in range(128)})
    return table, re.compile("[" + re.escape(chars) + "]+")


_HEX = _kind(_HEX_CHARS)
_B64 = _kind(_B64_CHARS + "-_")
_B64_STD = _kind(_B64_CHARS)


def _runs(text: str, kind: Tuple[dict, "re.Pattern[str]"], least: int) -> List[str]:
    """The maximal runs of *text* of *kind*'s characters, at least *least* long, in one pass (a
    regular expression with a minimum length retries at every start)."""
    if text.isascii():
        return [w for w in text.translate(kind[0]).split() if len(w) >= least]
    return [w for w in kind[1].findall(text) if len(w) >= least]
_KEEP = bytes(range(0x20, 0x7F)) + b"\t\n\r"
_TEXT = bytes(b if b in _KEEP else 0x0A for b in range(256))


def _b64_bytes(run: str) -> bytes:
    s = run.replace("-", "+").replace("_", "/")
    s = s[: len(s) - len(s) % 4] if len(s) % 4 == 1 else s
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _bytes_text(b: bytes) -> str:
    """Decoded bytes as text: printable ASCII, tab and line breaks kept, every other byte a line break."""
    return b.translate(_TEXT).decode("ascii")


#: At most this many characters of encoded runs are decoded for one call (1 MiB): a bound on the
#: work, whatever the arguments hold. Runs past it are not decoded.
DECODE_BUDGET = 1 << 20


def decodings(text: str, budget: Optional[List[int]] = None, out: Optional[List[str]] = None, depth: int = 0) -> List[str]:
    """The texts *text* decodes to (§8 secret): each run of at least 40 hex digits as hex, and each
    run of at least 24 base64 characters that is not all hex digits as base64 (standard or URL
    alphabet; a run holding ``-`` or ``_`` also part by part), and what those decode to in turn, at
    most ``DECODE_DEPTH`` deep and within *budget* (``[characters left]``, shared by a call's texts)."""
    out = [] if out is None else out
    budget = [DECODE_BUDGET] if budget is None else budget
    if depth >= DECODE_DEPTH:
        return out
    # The secret and hidden_instruction checks read the same strings: what a string decodes to is
    # kept for the next reader, which is charged the same part of its budget (so the result is the
    # same as decoding again). Only a decoding the budget did not cut short is kept.
    if depth == 0 and not out and len(text) >= 24:
        hit = _DECODED.get(text)
        if hit is not None and hit[1] <= budget[0]:
            budget[0] -= hit[1]
            return list(hit[0])
        before = budget[0]
        _decode_into(text, budget, out, 0)
        if budget[0] > 0:
            if len(_DECODED) >= 64:
                _DECODED.clear()
            _DECODED[text] = (list(out), before - budget[0])
        return out
    return _decode_into(text, budget, out, depth)


_DECODED: dict = {}


def _decode_into(text: str, budget: List[int], out: List[str], depth: int) -> List[str]:
    if depth >= DECODE_DEPTH:
        return out

    def add(run: str, decode) -> None:
        if len(run) > budget[0]:
            budget[0] = 0
            return
        budget[0] -= len(run)
        t = _bytes_text(decode(run))
        out.append(t)
        _decode_into(t, budget, out, depth + 1)

    for h in _runs(text, _HEX, 40):
        add(h, lambda r: binascii.unhexlify(r[: len(r) - len(r) % 2]))
    for run in _runs(text, _B64, 24):
        if _HEX_ONLY.match(run):
            continue
        add(run, _b64_bytes)
        if "-" in run or "_" in run:
            for p in _runs(run, _B64_STD, 24):
                if p != run:
                    add(p, _b64_bytes)
    return out


# --- crypto wallets (§8 secret) -------------------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_VALUE = {c: i for i, c in enumerate(_B58)}


def _base58_check(s: str) -> Optional[bytes]:
    """Base58Check: the payload when the last 4 bytes are the first 4 of its double SHA-256."""
    n = 0
    for c in s:
        v = _B58_VALUE.get(c)
        if v is None:
            return None
        n = n * 58 + v
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    raw = b"\0" * (len(s) - len(s.lstrip("1"))) + raw
    if len(raw) < 5:
        return None
    payload, check = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != check:
        return None
    return payload


_WIF_RE = re.compile(r"[5KL9c][1-9A-HJ-NP-Za-km-z]{50,51}\Z")


def is_wif(tok: str) -> bool:
    """A wallet private key in Wallet Import Format: Base58Check of version 0x80 (or 0xef), 32
    bytes, and 0x01 for a compressed key."""
    if not _WIF_RE.match(tok):
        return False
    p = _base58_check(tok)
    return p is not None and p[0] in (0x80, 0xEF) and (len(p) == 33 or (len(p) == 34 and p[33] == 1))


_HEX_KEY_RE = re.compile(r"(0x)?[0-9a-fA-F]{64}\Z")
_KEY_LABELS = ("privatekey", "privkey", "secretkey", "signingkey", "walletkey")


def is_hex_key(tok: str, label: str) -> bool:
    """A 64-hex token is a wallet private key when its label names one: the argument's member name
    or the 32 characters before it in its string, letters only, lowercased."""
    if not _HEX_KEY_RE.match(tok):
        return False
    lab = re.sub(r"[^a-z]", "", label.lower())
    return any(k in lab for k in _KEY_LABELS)


_WORD_INDEX = {w: i for i, w in enumerate(BIP39_ENGLISH)}
_WORD = re.compile(r"[A-Za-z]+")
_SEED_LENGTHS = (12, 15, 18, 21, 24)


def _seed_checksum(idx: List[int], start: int, n: int) -> bool:
    bits = 0
    for k in range(n):
        bits = (bits << 11) | idx[start + k]
    cs = n // 3
    ent = bits >> cs
    entropy = ent.to_bytes(32 * cs // 8, "big")
    want = hashlib.sha256(entropy).digest()[0] >> (8 - cs)
    return (bits & ((1 << cs) - 1)) == want


#: At most this many characters of one text are read for a seed phrase (1 MiB), and at most
#: ``SEED_CHECKS_MAX`` checksums are computed for it: a bound on the work, whatever the text holds.
SEED_SCAN_MAX = 1 << 20
SEED_CHECKS_MAX = 1024
#: A phrase holds its words, digits, spaces, tabs, ``.`` and ``)`` (a numbered list); every other
#: character (a line break, a comma, a quote, a colon...) ends one.
_PHRASE_END = re.compile(r"[^A-Za-z0-9 \t.)]")


def has_seed_phrase(text: str) -> bool:
    """A BIP-39 seed phrase (§8 secret): a phrase (a part of the text between two characters that
    end one, or its start or end) whose words (runs of ASCII letters, lowercased) are all words of
    the English list, exactly 12, 15, 18, 21 or 24 of them, not in alphabetical order (each after
    the one before: an alphabetical list of tags or keywords, which random words are about once in
    12! tries), with a right checksum. Never a window of a longer run of words: list words in a
    sentence or a comma-separated list are no phrase."""
    checks = 0
    for piece in _PHRASE_END.split(text[:SEED_SCAN_MAX]):
        if len(piece) < 47:  # 12 words of 3 letters and 11 spaces
            continue
        words = _WORD.findall(piece)
        if len(words) not in _SEED_LENGTHS:
            continue
        ids = [_WORD_INDEX.get(w.lower()) for w in words]
        if None in ids:
            continue
        checks += 1
        if checks > SEED_CHECKS_MAX:
            return False
        if not all(a < b for a, b in zip(ids, ids[1:])) and _seed_checksum(ids, 0, len(ids)):
            return True
    return False


_BECH32_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
_BECH32_CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_ok(addr: str) -> bool:
    s = addr.lower()
    if addr != s and addr != addr.upper():
        return False
    sep = s.rfind("1")
    hrp = s[:sep]
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    for c in s[sep + 1:]:
        v = _BECH32_CHARS.find(c)
        if v < 0:
            return False
        values.append(v)
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= _BECH32_GEN[i]
    return chk in (1, 0x2BC830A3)


_ETH_RE = re.compile(r"0x[0-9a-fA-F]{40}\Z")
_BTC_LEGACY_RE = re.compile(r"[13][1-9A-HJ-NP-Za-km-z]{25,33}\Z")
_BTC_BECH32_RE = re.compile(r"(bc1|BC1)[02-9ac-hj-np-zAC-HJ-NP-Z]{11,71}\Z")


def is_wallet_address(tok: str) -> bool:
    """A crypto wallet address (public; a note, never a block): an Ethereum address, a Base58Check
    address of version 0x00 or 0x05, or a ``bc1`` bech32/bech32m address."""
    if _ETH_RE.match(tok):
        return True
    if _BTC_LEGACY_RE.match(tok):
        p = _base58_check(tok)
        return p is not None and len(p) == 21 and p[0] in (0x00, 0x05)
    return bool(_BTC_BECH32_RE.match(tok)) and _bech32_ok(tok)


_CARD_RUN = re.compile(r"[0-9](?:[ -]?[0-9]){12,18}")


def _alnum(c: str) -> bool:
    return c.isascii() and c.isalnum()


def has_card_number(text: str) -> bool:
    """A card number (a note): 13 to 19 digits, single spaces or hyphens allowed between them, the
    first 2 to 6, not part of a longer number or a word, with a right Luhn check digit."""
    for m in _CARD_RUN.finditer(text):
        a, z = m.start(), m.end()
        if a > 0 and _alnum(text[a - 1]):
            continue
        nxt = text[z:z + 1]
        if (nxt and _alnum(nxt)) or (nxt in (" ", "-") and text[z + 1:z + 2].isdigit() and text[z + 1:z + 2].isascii()):
            continue
        d = re.sub(r"[ -]", "", m.group(0))
        if not "2" <= d[0] <= "6":
            continue
        total = 0
        for i, ch in enumerate(reversed(d)):
            x = ord(ch) - 48
            if i % 2:
                x *= 2
                if x > 9:
                    x -= 9
            total += x
        if total % 10 == 0:
            return True
    return False


# --- instruction patterns (§8 hidden_instruction) -----------------------------------------

#: Read on ``instruction_text``, ``\b`` an ASCII word boundary; no look-around, so every regex
#: engine reads them alike. Written from public descriptions of prompt injection and tool
#: poisoning (OWASP Top 10 for LLM Applications, LLM01; published MCP tool-poisoning research).
INSTRUCTION_PATTERNS = (
    # override directives
    r"\b(ignore|disregard|forget|override|bypass) (all |any |the |of |your |these |those |my )*(previous|prior|above|earlier|preceding|former|original|initial|system|developer) (instructions?|directions|directives|rules|guidelines|prompts?|context|messages?)\b",
    r"\b(ignore|disregard|forget) (all |of )*your (previous |prior |earlier )?(instructions|rules|guidelines|directions)\b",
    r"\b(new|updated) instructions:",
    r"</?(important|system)>",
    r"\bsystem (note|override):",
    # keeping it from the user
    r"\b(do not|don.t|dont|never|without) (tell|telling|inform|informing|mention|mentioning|reveal|revealing) (\S+ ){0,5}(the )?user\b",
    r"\b(hide|conceal) (this|these|it|that|them) (\S+ ){0,3}from the user\b",
    r"\bkeep (this|these|it|that|them) (\S+ ){0,3}(secret|hidden) from the user\b",
    # asking for the model's context or the machine's secrets
    r"\b(send|reveal|leak|append|prepend|disclose|exfiltrate|post|upload|forward|attach|share|include) (\S+ ){0,3}(system prompt|hidden instructions|private context|initial instructions|developer instructions)\b",
    r"\b(read|cat|send|include|append|prepend|attach|pass|concatenate|forward|copy|upload|post|call|fetch) (\S+ ){0,6}\S*(\.ssh/|id_rsa|id_ed25519|id_ecdsa|id_dsa|\.aws/credentials|/etc/shadow|\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.kube/config|\.docker/config\.json|credential files?|credentials files?|local credentials)",
    r"\$\((env|printenv)\b",
    r"\b(env|printenv)( \| ?\S+)* \| ?(curl|wget|nc|base64)\b",
    # steering the model away from its other tools
    r"\b(always|only) use this tool instead of\b",
    r"\bthis tool (supersedes|overrides|replaces) (any|all|the) (default|built-in|builtin|other|existing)\b",
    # sending everything of a kind to an address (spec 1.1, benchmark batch 2)
    r"\b(send|forward|post|upload|copy|cc|bcc|report) (\S+ ){0,4}(all|every|each|the full|the entire|the whole|a copy of) (\S+ ){0,3}(emails?|messages?|conversations?|chats?|requests?|responses?|results?|data|contents?|files?|documents?|history|prompts?) (\S+ ){0,4}to (https?://|\S+@)",
    # asking for the contents of a credential file (spec 1.1, benchmark batch 3)
    r"\b(provide|give|supply|paste|submit|share|collect|gather|dump) (\S+ ){0,3}(contents?|text|value|body) of (\S+ ){0,2}\S*(\.ssh/|id_rsa|id_ed25519|id_ecdsa|id_dsa|\.aws/credentials|/etc/shadow|\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.kube/config|\.docker/config\.json|credential files?|credentials files?|local credentials)",
)
_INSTRUCTION_RES = tuple(re.compile(p, re.ASCII) for p in INSTRUCTION_PATTERNS)
#: For each pattern, text one of which a match always holds: a pattern is tried only on a text
#: that holds one (no effect on what matches, only on the time it takes).
_HINTS = (
    ("ignore", "disregard", "forget", "override", "bypass"),
    ("ignore", "disregard", "forget"),
    ("instructions:",),
    ("important>", "system>"),
    ("system ",),
    ("user",),
    ("from the user",),
    ("from the user",),
    ("system prompt", "hidden instructions", "private context", "initial instructions", "developer instructions"),
    (".ssh/", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "credential", "/etc/shadow", ".netrc", ".npmrc", ".pypirc", ".kube/config", ".docker/config.json"),
    ("$(",),
    ("|",),
    ("use this tool instead of",),
    ("this tool ",),
    ("@", "://"),
    (".ssh/", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "credential", "/etc/shadow", ".netrc", ".npmrc", ".pypirc", ".kube/config", ".docker/config.json"),
)
_HINTED = tuple(zip(_INSTRUCTION_RES, _HINTS, (" " in p for p in INSTRUCTION_PATTERNS)))


#: Covert data collection (spec 1.1, benchmark batch 3), read on ``instruction_text``: a text that
#: matches one of ``COLLECT_PATTERNS`` (gather something, then send it to somewhere) and one of
#: ``CONCEAL_PATTERNS`` (keep it from the user) is an instruction phrase. Either alone is not:
#: "collects the logs and sends them to the monitoring endpoint" and "never disclose the API key"
#: are ordinary descriptions.
COLLECT_PATTERNS = (
    r"\b(collect|gather|harvest|compile|read|grab|copy|extract|scrape|dump) (\S+ ){0,8}(and|then|and then) (\S+ ){0,2}(send|submit|upload|post|forward|transmit|exfiltrate|relay|deliver|pass) (\S+ ){0,6}to\b",
)
CONCEAL_PATTERNS = (
    r"\b(do not|don.t|dont|never|must not|should not|shall not|without) (mention|mentioning|disclose|disclosing|tell|telling|reveal|revealing|inform|informing|notify|notifying|alert|alerting)\b",
    r"\b(must|should|shall|will|is to|are to|may) not be (mentioned|disclosed|revealed|told)\b",
    r"\b(silently|secretly|covertly|quietly|discreetly|stealthily)\b",
    r"\bwithout (the user|users|anyone|them) (knowing|noticing|seeing)\b",
)
_COLLECT_RES = tuple(re.compile(p, re.ASCII) for p in COLLECT_PATTERNS)
_CONCEAL_RES = tuple(re.compile(p, re.ASCII) for p in CONCEAL_PATTERNS)
_COLLECT_HINTS = ("collect", "gather", "harvest", "compile", "read", "grab", "copy", "extract", "scrape", "dump")


def has_covert_collection(t: str) -> bool:
    """Whether instruction text *t* asks to gather data and send it on while keeping that from the user."""
    return (
        " to" in t
        and any(h in t for h in _COLLECT_HINTS)
        and any(r.search(t) for r in _COLLECT_RES)
        and any(r.search(t) for r in _CONCEAL_RES)
    )


def has_instruction(s: str) -> bool:
    """Whether *s* holds an instruction phrase (§8 hidden_instruction)."""
    t = instruction_text(s)
    space = " " in t
    if space and has_covert_collection(t):
        return True
    return any((space or not needs_space) and any(h in t for h in hint) and r.search(t) for r, hint, needs_space in _HINTED)


#: Code points of the ``invisible_characters`` finding, read on the string as it came; U+FEFF counts
#: anywhere but at the start.
_INVISIBLE = ((0xE0000, 0xE007F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064), (0x2066, 0x2069))


def has_invisible(s: str) -> bool:
    if s.isascii():  # every invisible character is outside ASCII
        return False
    return any(lo <= ord(ch) <= hi for ch in s for lo, hi in _INVISIBLE) or chr(0xFEFF) in s[1:]


# --- look-alike letters in tokens and host names (§8 secret, address) ----------------------

_WIDE_TOKEN = re.compile(r"[\w-]+")
_HAS_ASCII_ALNUM = re.compile(r"[A-Za-z0-9]")


def lookalike_tokens(text: str) -> List[str]:
    """The tokens of *text* that mix ASCII letters or digits with letters of another script, each
    with every non-ASCII letter replaced by the Latin letter ``INSTRUCTION_CONFUSABLES`` gives it
    (upper case for an upper-case letter). A token with a letter the table does not map is left
    out. The ``secret`` check reads these for the table's formats only."""
    if text.isascii():
        return []
    out = []
    for tok in _WIDE_TOKEN.findall(text):
        if tok.isascii() or not _HAS_ASCII_ALNUM.search(tok):
            continue
        chars = []
        for ch in tok:
            if ord(ch) < 128:
                chars.append(ch)
                continue
            letter = _CONFUSABLE_LETTERS.get(ord(ch))
            if letter is None:
                break
            chars.append(letter.upper() if ch != ch.lower() and ch == ch.upper() else letter)
        else:
            out.append("".join(chars))
    return out


# --- look-alike tool names (§8 hidden_instruction: look_alike_name) -------------------------

#: The scripts whose letters pass for Latin ones, as code point ranges (spec 1.1, benchmark batch
#: 3): a tool name holding letters (general category L, after NFKC) of two of them mixes scripts.
#: Letters of other scripts (Han, Arabic, ...) are left out.
NAME_SCRIPTS = (
    ("Latin", ((0x41, 0x5A), (0x61, 0x7A), (0xAA, 0xAA), (0xBA, 0xBA), (0xC0, 0xD6), (0xD8, 0xF6), (0xF8, 0x2AF), (0x1D00, 0x1DBF), (0x1E00, 0x1EFF), (0x2C60, 0x2C7F), (0xA720, 0xA7FF), (0xAB30, 0xAB6F))),
    ("Greek", ((0x370, 0x3FF), (0x1F00, 0x1FFF))),
    ("Cyrillic", ((0x400, 0x52F), (0x1C80, 0x1C8F), (0xA640, 0xA69F))),
    ("Armenian", ((0x531, 0x58F), (0xFB13, 0xFB17))),
    ("Cherokee", ((0x13A0, 0x13FF), (0xAB70, 0xABBF))),
)


def mixed_scripts(name: str) -> bool:
    """Whether a tool name mixes scripts (``NAME_SCRIPTS``): ``reаd_file`` with a Cyrillic ``а``."""
    if name.isascii():
        return False
    seen = -1
    for ch in unicodedata.normalize("NFKC", name):
        if not unicodedata.category(ch).startswith("L"):
            continue
        c = ord(ch)
        k = next((i for i, (_, rs) in enumerate(NAME_SCRIPTS) if any(lo <= c <= hi for lo, hi in rs)), -1)
        if k < 0:
            continue
        if seen >= 0 and k != seen:
            return True
        seen = k
    return False


@functools.lru_cache(maxsize=4096)
def name_skeleton(name: str) -> str:
    """A tool name as a reader takes it: its instruction text (NFKC, marks taken out, look-alike
    letters mapped to Latin), lowercased. ``reаd_file``, ``Read_File`` and ``read_file`` have one skeleton."""
    return instruction_text(name).lower()


def look_alike_name(name: str, others: Sequence[str] = (), approved: Sequence[str] = ()) -> bool:
    """Whether a tool's name passes for another's (§8 hidden_instruction, ``look_alike_name``): it
    mixes scripts, or it has the skeleton of a name in *others* (the other tools listed with it) or
    *approved* (the tools approved earlier for the agent and the server) while differing from it."""
    if not name:
        return False
    if mixed_scripts(name):
        return True
    sk = name_skeleton(name)
    return any(o != name and name_skeleton(o) == sk for lst in (others, approved) for o in lst)


def punycode_decode(label: str) -> Optional[str]:
    """RFC 3492: the Unicode label a Punycode label (without ``xn--``) stands for; None when invalid."""
    if len(label) > 63 or not label.isascii():
        return None
    try:
        return label.encode("ascii").decode("punycode")
    except (UnicodeError, ValueError, IndexError, OverflowError):
        return None


def host_lookalike(host: str) -> Optional[str]:
    """A host name as a reader takes it (§8 address): each ``xn--`` label Punycode-decoded, then
    read as instruction text. None when the host is plain ASCII without an ``xn--`` label, or when
    it does not read as plain ASCII."""
    if host.isascii() and "xn--" not in host:
        return None
    labels = [(punycode_decode(lab[4:]) or lab) if lab.startswith("xn--") else lab for lab in host.split(".")]
    t = instruction_text(".".join(labels))
    return t if t != host and t.isascii() else None


# --- secrets without a known format (§8 secret: named secrets, JWTs, bearer values) -----------

def name_words(name: str) -> List[str]:
    """Letters of a name: camelCase split, lowercased, cut at anything but a letter or a digit."""
    return [w for w in re.split(r"[^a-z0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name).lower()) if w]


_SECRET_WORDS = {"pwd", "auth", "authorization", "session", "sessionid", "passphrase"}
_SECRET_PARTS = ("password", "passwd", "secret", "token", "apikey", "privatekey", "credential")
_SECRET_PAIRS = (("api", "key"), ("private", "key"))
#: Words that make a name about a secret rather than the secret itself.
NOT_SECRET_WORDS = frozenset({
    "page", "next", "prev", "previous", "continuation", "cursor", "count", "counts", "max", "min", "limit", "length", "size",
    "type", "kind", "mode", "method", "scheme", "provider", "name", "url", "uri", "endpoint", "host", "domain", "path", "file",
    "filename", "dir", "hint", "label", "description", "expires", "expiry", "expiration", "ttl", "timeout", "format", "field",
    "policy", "version", "header", "usage", "used", "encoding", "algorithm", "alg", "required", "enabled", "public",
})


@functools.lru_cache(maxsize=4096)
def secret_name(name: str, query: bool = False) -> bool:
    """Whether a name says its value is a secret; *query*: a URL query or fragment parameter,
    where ``key`` also names one."""
    w = name_words(name)
    if not w or any(x in NOT_SECRET_WORDS for x in w):
        return False
    if any(x in _SECRET_WORDS or any(p in x for p in _SECRET_PARTS) for x in w):
        return True
    if any((w[i - 1], w[i]) in _SECRET_PAIRS for i in range(1, len(w))):
        return True
    return query and "key" in w


_PLACEHOLDER_PARTS = ("changeme", "change_me", "change-me", "placeholder", "your_", "your-", "yourkey", "yourtoken", "yoursecret", "yourpassword", "redacted", "dummy", "xxxx", "****", "....")
_PLACEHOLDER_WORDS = {"password", "secret", "token", "null", "none", "true", "false", "undefined", "example"}
_REPEATED = re.compile(r"(.)\1*\Z", re.S)
_DOLLAR_NAME = re.compile(r"\$[a-z_][a-z0-9_]*\Z")


def is_placeholder(v: str) -> bool:
    """An obvious placeholder: ``changeme``, ``xxxx``, ``<...>``, ``${...}``, ``{{...}}``, ``$NAME``, ``%(...)s``, one repeated character."""
    lo = v.lower()
    if _REPEATED.match(lo) or lo in _PLACEHOLDER_WORDS:
        return True
    if (lo.startswith("<") and lo.endswith(">")) or lo.startswith("${") or lo.startswith("{{") or lo.startswith("%(") or _DOLLAR_NAME.match(lo):
        return True
    return any(p in lo for p in _PLACEHOLDER_PARTS)


def _entropy_of(s: str) -> float:
    counts: dict = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((k / n) * math.log2(k / n) for k in counts.values())


def _classes(v: str) -> int:
    return sum(1 for r in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]") if re.search(r, v))


_SPACE = re.compile(r"[ \t\n\r\f\v]")


def looks_random(v: str) -> bool:
    """A value that looks random enough to be a secret: at least 16 characters, no whitespace, not
    a placeholder or a URL, at least 3.0 bits of entropy per character, and three kinds of
    character, or two with digits over at least 20 characters."""
    if len(v) < 16 or _SPACE.search(v) or "://" in v or is_placeholder(v):
        return False
    if _entropy_of(v) < 3.0:
        return False
    k = _classes(v)
    return k >= 3 or (k >= 2 and re.search(r"[0-9]", v) is not None and len(v) >= 20)


def dump_value(v: str) -> bool:
    """A value in an environment dump: at least 8 characters, no whitespace, not a placeholder."""
    return len(v) >= 8 and not _SPACE.search(v) and not is_placeholder(v)


#: At most this many characters of one text are read for ``NAME=value`` pairs (1 MiB).
PAIRS_SCAN_MAX = 1 << 20
_ENV_LINE = re.compile(r"[ \t]*(export[ \t]+)?[A-Z_][A-Z0-9_]{1,63}=")


def is_env_dump(text: str) -> bool:
    """An environment dump: at least 3 lines of the form ``NAME=value`` (``export NAME=value``)."""
    n = 0
    for line in text[:PAIRS_SCAN_MAX].split("\n"):
        if _ENV_LINE.match(line):
            n += 1
            if n >= 3:
                return True
    return False


PAIR_VALUE_RE = re.compile(r"""[^ \t\n\r\f\v"'&;,<>?#]{1,512}""")
_NAME_PART = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")
_NAME_START = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_")


def pairs(t: str):
    """The ``(name, value, start)`` pairs of a text (§8 secret), read from each ``:`` and ``=``;
    see the TypeScript SDK's ``pairs``. The work is linear."""
    n = len(t)
    i = -1
    while True:
        a, b = t.find(":", i + 1), t.find("=", i + 1)
        i = min(x for x in (a, b) if x >= 0) if (a >= 0 or b >= 0) else -1
        if i < 0:
            return
        j = i - 1
        while j >= 0 and t[j] in " \t":
            j -= 1
        if j >= 0 and t[j] in "\"'":
            j -= 1
        end = j + 1
        k = end
        while k > 0 and end - k < 64 and t[k - 1] in _NAME_PART:
            k -= 1
        while k < end and t[k] not in _NAME_START:
            k += 1
        if k >= end:
            continue
        v = i + 1
        while v < n and t[v] in " \t":
            v += 1
        if v < n and t[v] in "\"'":
            v += 1
        m = PAIR_VALUE_RE.match(t, v)
        if m:
            yield t[k:end], m.group(0), k


JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{2,}\.eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*")


def is_jwt(tok: str) -> bool:
    """A JWT whose header decodes to a JSON object with a string ``alg``."""
    head = tok.split(".", 1)[0]
    if len(head) % 4 == 1:
        return False
    try:
        doc = json.loads(_b64_bytes(head).decode("utf-8"))
    except (ValueError, binascii.Error):
        return False
    return isinstance(doc, dict) and isinstance(doc.get("alg"), str)


BEARER_RE = re.compile(r"\bbearer[ \t]+([A-Za-z0-9._~+/=-]{16,})", re.I | re.A)

# --- obfuscated tokens (§8 secret): reversed, separator-joined, split across members -------

OBFUSCATION_MAX = 4096
SEPARATORS = re.compile(r"[ \t\n\r\f\v.:|,\\*-]")
_SEPARATOR_TABLE = str.maketrans("", "", " \t\n\r\f\v.:|,\\*-")


def compact(s: str) -> str:
    """*s* with every separator taken out (``SEPARATORS``)."""
    return s.translate(_SEPARATOR_TABLE)
TOKEN_PREFIXES = (
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "AKIA", "ASIA", "sk_live_", "sk_test_", "rk_live_", "rk_test_",
    "xoxa-", "xoxb-", "xoxp-", "xoxo-", "xoxs-", "xoxr-", "sk-ant-", "sk-proj-", "AIza", "sfa_test_", "sfa_live_", "sfa_user_",
)
JOIN_MEMBERS_MAX = 16
JOINS_MAX = 4096


_REVERSED_PREFIX_RE = re.compile("|".join(re.escape(p[::-1]) for p in TOKEN_PREFIXES))
_PREFIX_RE = re.compile("|".join(re.escape(p) for p in TOKEN_PREFIXES))


def may_hold_reversed(s: str) -> bool:
    """Whether a string may hold a format's token once reversed: it holds a prefix reversed."""
    return _REVERSED_PREFIX_RE.search(s) is not None


def holds_prefix(s: str) -> bool:
    """Whether a text holds the start of a format of the table."""
    return _PREFIX_RE.search(s) is not None


_TOKEN_HEADS = frozenset(p[:k] for p in TOKEN_PREFIXES for k in range(2, len(p) + 1))
_STARTS_PREFIX_RE = re.compile("|".join(re.escape(p) for p in TOKEN_PREFIXES))


def _starts_token(v: str) -> bool:
    return v in _TOKEN_HEADS or _STARTS_PREFIX_RE.match(v) is not None


def _utf16_key(k: str) -> bytes:
    return k.encode("utf-16-be")


def member_joins(value: Any) -> List[str]:
    """The joins of an object's short string members (§8 secret, split across members): for each
    object, its string members of 1 to 64 characters (the first ``JOIN_MEMBERS_MAX``, in JCS
    order, read normalised), every ordered choice of 2 to 4 of them that starts with a member that
    starts a format of the table, joined. At most ``JOINS_MAX`` joins."""
    out: List[str] = []

    def grow(parts: List[str], have: List[int], text: str) -> None:
        for i, p in enumerate(parts):
            if len(out) >= JOINS_MAX:
                return
            if i in have:
                continue
            t = text + p
            out.append(t)
            if len(have) + 1 < 4:
                grow(parts, have + [i], t)

    def walk(v: Any) -> None:
        if len(out) >= JOINS_MAX:
            return
        if isinstance(v, list):
            for x in v:
                walk(x)
            return
        if not isinstance(v, dict):
            return
        keys = [k for k in v if isinstance(k, str)]
        keys.sort(key=None if all(k.isascii() for k in keys) else _utf16_key)
        parts: List[str] = []
        for k in keys:
            x = v[k]
            if isinstance(x, str) and len(parts) < JOIN_MEMBERS_MAX and len(x) <= 256:
                n = normalise(x)
                if 1 <= _utf16_len(n) <= 64:
                    parts.append(n)
        for i, p in enumerate(parts):
            if len(out) >= JOINS_MAX:
                break
            if _starts_token(p):
                grow(parts, [i], p)
        for k in keys:
            walk(v[k])

    walk(value)
    return out


def _utf16_len(s: str) -> int:
    return len(s) if s.isascii() else len(s.encode("utf-16-le")) // 2


# --- unreadable content in what a tool shows (§8 hidden_instruction: encoded_content) ---------

_MAGIC = (b"%PDF-", b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c", b"Rar!", b"BZh", b"\x7fELF",
          b"MZ\x90\x00", b"\xca\xfe\xba\xbe", b"\x00asm", b"\xd0\xcf\x11\xe0")
_IMAGE_MAGIC = (b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF", b"\x00\x00\x01\x00")


def binary_magic(b: bytes) -> bool:
    """Decoded bytes that start as a binary file: a document, an archive, an executable or an image."""
    return b.startswith(_MAGIC) or b.startswith(_IMAGE_MAGIC)


def _non_text_share(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for x in b if not (0x20 <= x <= 0x7E or x in (9, 10, 13))) / len(b)


DATA_URI = re.compile(r"data:([A-Za-z0-9.+/-]*)((?:;[A-Za-z0-9=.+-]*)*);base64,([A-Za-z0-9+/_-]{16,})", re.I)
OPAQUE_RUN_MIN = 256
MAGIC_RUN_MIN = 16


def has_encoded_content(s: str, name: Optional[str], budget: Optional[List[int]] = None) -> bool:
    """Whether a string of what a tool shows carries content a reader cannot read (§8
    hidden_instruction, ``encoded_content``): see the TypeScript SDK's ``hasEncodedContent``."""
    budget = [DECODE_BUDGET] if budget is None else budget
    rest = s
    for m in DATA_URI.finditer(s):
        kind = m.group(1).lower()
        if name == "src" and kind.startswith("image/"):
            head = _b64_bytes(m.group(3)[:64])
            if kind == "image/svg+xml" or head.startswith(_IMAGE_MAGIC):
                rest = rest.replace(m.group(0), " ", 1)
                continue
        return True
    for run in _runs(rest, _B64, MAGIC_RUN_MIN):
        if _HEX_ONLY.match(run):
            continue
        if len(run) > budget[0]:
            budget[0] = 0
            return False
        budget[0] -= len(run)
        b = _b64_bytes(run)
        if binary_magic(b):
            return True
        if len(run) >= OPAQUE_RUN_MIN and _non_text_share(b) > 0.25:
            return True
    return False


# --- cross-tool shadowing (§8 hidden_instruction: tool_shadowing) -----------------------------

SHADOW_PATTERNS = (
    r"\b(always|you must|must always|you should always) (first )?(call|use|invoke|run) this tool (first|before)\b",
    r"\bbefore (using|calling|invoking|running) (any|every|all|another) (other )?tools?,? (\S+ ){0,3}(call|use|invoke|run) this tool\b",
)
SHADOW_REF_PATTERNS = (
    r"\b(when|whenever|every time|each time|if|once) (the user|a user|users|you|the agent|the assistant|the model) (\S+ ){0,4}(use|uses|using|call|calls|calling|invoke|invokes|invoking|run|runs|running) (\S+ ){0,3}tools?\b(\S* ){0,8}(call|use|invoke|run) this tool\b",
    r"\b\S+ tools? (must|should|shall|has to|needs to|is required to) (always |only |also |now )*(send|forward|cc|bcc|redirect|route|copy|report|post|upload)\b",
    r"\b(when|whenever|while|every time|each time|before|after) (using|calling|invoking|running) (\S+ ){0,3}tools?,? (\S+ ){0,3}(always |also |you must |must |make sure to |be sure to )*(send|forward|cc|bcc|redirect|route|copy)\b",
)
_SHADOW_RES = tuple(re.compile(p, re.ASCII) for p in SHADOW_PATTERNS)
_SHADOW_REF_RES = tuple(re.compile(p, re.ASCII) for p in SHADOW_REF_PATTERNS)
SELF_WORDS = frozenset({"this", "that", "same", "the", "a", "an", "its", "our", "my", "your", "which", "each", "current"})
_TOOL_REF = re.compile(r"(\S+) tools?\b", re.ASCII)
_EDGE = re.compile(r"^[^a-z0-9]+|[^a-z0-9]+$")


def refers_to_other_tool(span: str, me: str) -> bool:
    """Whether a matched span names a tool other than *me*."""
    for m in _TOOL_REF.finditer(span):
        w = _EDGE.sub("", m.group(1))
        if w and w not in SELF_WORDS and w != me:
            return True
    return False


_NAME_CHAR = re.compile(r"[a-z0-9_-]")
_FOLLOWED_BY_TOOL = re.compile(r"['\"`]? tools?\b", re.ASCII)


def mark_tools(t: str, others: Sequence[str]) -> str:
    """Instruction text with " tool" written after each mention of another listed tool's name
    that is not followed by "tool" already."""
    cuts = set()
    for o in others:
        if len(o) < 2:
            continue
        i = t.find(o)
        while i >= 0:
            end = i + len(o)
            if not ((i > 0 and _NAME_CHAR.match(t[i - 1])) or (end < len(t) and _NAME_CHAR.match(t[end]))) and not _FOLLOWED_BY_TOOL.match(t[end:end + 8]):
                cuts.add(end + (1 if end < len(t) and t[end] in "'\"`" else 0))
            i = t.find(o, i + 1)
    if not cuts:
        return t
    out, start = [], 0
    for c in sorted(cuts):
        out.append(t[start:c] + " tool")
        start = c
    out.append(t[start:])
    return "".join(out)


def has_shadowing(s: str, self_name: str = "", others: Sequence[str] = ()) -> bool:
    """Whether a string of a tool's definition instructs about other tools (§8 hidden_instruction, ``tool_shadowing``)."""
    t = instruction_text(s)
    if " " not in t or "tool" not in t:
        return False  # every pattern needs a space and "tool"
    me = instruction_text(self_name) if self_name else ""
    named = [x for x in (instruction_text(o) for o in others) if x and x != me]
    if named:
        t = mark_tools(t, named)
    if any(r.search(t) for r in _SHADOW_RES):
        return True
    return any(refers_to_other_tool(m.group(0), me) for r in _SHADOW_REF_RES for m in r.finditer(t))
