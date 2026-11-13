"""RFC 8785 JSON Canonicalization Scheme (JCS).

Floats are serialized like ECMAScript ``Number.prototype.toString`` (IEEE
double); ints must lie within +-(2^53-1) (SPEC §1). Object keys are sorted by
UTF-16 code units and strings are escaped like ``JSON.stringify``. Lone
surrogates, NaN and Infinity are rejected.
"""

from __future__ import annotations

import json
import math
from typing import Any

__all__ = ["canonicalize", "dumps", "assert_portable_numbers"]

MAX_SAFE_INT = 2**53 - 1


def canonicalize(value: Any) -> bytes:
    """The JCS bytes of *value* (dict, list, str, int, float, bool or None)."""
    out: list[str] = []
    _write(value, out)
    return "".join(out).encode("utf-8")


def dumps(value: Any) -> str:
    """JCS as a str (for writing JSON lines)."""
    return canonicalize(value).decode("utf-8")


def _write(v: Any, out: list[str]) -> None:
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, str):
        out.append(_string(v))
    elif isinstance(v, int):
        if not -MAX_SAFE_INT <= v <= MAX_SAFE_INT:
            raise ValueError(f"unsafe_integer: {v} is beyond +-(2^53-1); send it as a string")
        out.append(str(v))
    elif isinstance(v, float):
        out.append(_number(v))
    elif isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise TypeError(f"JCS object keys must be strings, got {type(k).__name__}")
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be", "surrogatepass"))
        out.append("{")
        for i, (k, item) in enumerate(items):
            if i:
                out.append(",")
            out.append(_string(k))
            out.append(":")
            _write(item, out)
        out.append("}")
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for i, item in enumerate(v):
            if i:
                out.append(",")
            _write(item, out)
        out.append("]")
    else:
        raise TypeError(f"JCS cannot encode {type(v).__name__}")


def _string(s: str) -> str:
    for ch in s:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise ValueError("JCS strings must not contain lone surrogates")
    # json.dumps(ensure_ascii=False) escapes exactly what JSON.stringify escapes:
    # quote, backslash, \b \f \n \r \t, and other C0 controls as lowercase \u00xx.
    return json.dumps(s, ensure_ascii=False)


def _number(x: float) -> str:
    if math.isnan(x) or math.isinf(x):
        raise ValueError("JCS does not allow NaN or Infinity")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    # repr() gives the shortest round-trip digits, the same digits ECMAScript picks.
    mant, _, exp = repr(abs(x)).partition("e")
    int_part, _, frac = mant.partition(".")
    if frac == "0":
        frac = ""
    digits = (int_part + frac).lstrip("0")
    # n: position of the decimal point relative to the start of `digits`
    n = len(int_part.lstrip("0")) if int_part.strip("0") else -(len(frac) - len(frac.lstrip("0")))
    n += int(exp or 0)
    digits = digits.rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + s


def is_unsafe_float(x: float) -> bool:
    """An integer-valued float that JCS writes as an integer literal beyond +-(2^53-1)."""
    return math.isfinite(x) and x.is_integer() and MAX_SAFE_INT < abs(x) < 1e21


def assert_portable_numbers(value: Any) -> None:
    """Content the SDK signs must not hold floats that JCS writes as integer literals
    beyond +-(2^53-1) (e.g. 1e20 -> 100000000000000000000): any implementation that
    re-reads that text would reject it (SPEC §1). Raises ValueError on the first one."""
    if isinstance(value, float) and is_unsafe_float(value):
        raise ValueError(f"unsafe_integer: {value!r} is written as an integer beyond +-(2^53-1); send it as a string")
    if isinstance(value, dict):
        for v in value.values():
            assert_portable_numbers(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            assert_portable_numbers(v)
