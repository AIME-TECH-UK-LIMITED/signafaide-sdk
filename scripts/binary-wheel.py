#!/usr/bin/env python3
"""A PyPI wheel for `signafaide-verify` from a release binary, so the wheel holds exactly the file
that is published, checksummed and attested on GitHub Releases (no second build):

    python3 scripts/binary-wheel.py <binary> <platform tag> <out dir>

The binary goes in as the `signafaide-verify` script (`.exe` on Windows); the metadata comes from
verifier/pyproject.toml, the version from verifier/Cargo.toml, the description from
verifier/README.md, and LICENSE and verifier/THIRD-PARTY-NOTICES.md (the crates in the binary) are included. Platform tags used by the release workflow:

    linux (static musl): manylinux_2_17_<arch>.manylinux2014_<arch>.musllinux_1_1_<arch>
    macOS: macosx_10_12_x86_64, macosx_11_0_arm64     Windows: win_amd64

Standard library only (Python 3.11 or later, for tomllib).
"""

from __future__ import annotations

import base64
import hashlib
import io
import re
import sys
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "verifier"
# A fixed time for every entry, so the same binary always gives the same wheel.
STAMP = (2020, 1, 1, 0, 0, 0)


def digest(data: bytes) -> str:
    return (
        "sha256="
        + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    )


def metadata(project: dict, version: str) -> str:
    lines = [
        "Metadata-Version: 2.4",
        f"Name: {project['name']}",
        f"Version: {version}",
        f"Summary: {project['description']}",
        f"Requires-Python: {project['requires-python']}",
        f"License-Expression: {project['license']}",
        "License-File: LICENSE",
        "License-File: THIRD-PARTY-NOTICES.md",
        f"Keywords: {','.join(project.get('keywords', []))}",
        *(f"Classifier: {c}" for c in project.get("classifiers", [])),
        *(f"Project-URL: {k}, {v}" for k, v in project.get("urls", {}).items()),
        "Description-Content-Type: text/markdown",
        "",
        (VERIFIER / "README.md").read_text(encoding="utf-8"),
    ]
    return "\n".join(lines)


def main(binary: str, tag: str, out: str) -> Path:
    project = tomllib.loads((VERIFIER / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    version = re.search(
        r'^version = "([^"]+)"', (VERIFIER / "Cargo.toml").read_text(), re.M
    ).group(1)
    name = project["name"].replace("-", "_")
    exe = ".exe" if tag.startswith("win") else ""
    info = f"{name}-{version}.dist-info"
    files = {
        f"{name}-{version}.data/scripts/signafaide-verify{exe}": (
            Path(binary).read_bytes(),
            0o755,
        ),
        f"{info}/METADATA": (metadata(project, version).encode(), 0o644),
        f"{info}/WHEEL": (
            "\n".join(
                [
                    "Wheel-Version: 1.0",
                    "Generator: signafaide binary-wheel.py",
                    "Root-Is-Purelib: false",
                ]
                + [f"Tag: py3-none-{t}" for t in tag.split(".")]
            ).encode()
            + b"\n",
            0o644,
        ),
        f"{info}/licenses/LICENSE": ((ROOT / "LICENSE").read_bytes(), 0o644),
        f"{info}/licenses/THIRD-PARTY-NOTICES.md": ((VERIFIER / "THIRD-PARTY-NOTICES.md").read_bytes(), 0o644),
    }
    record = (
        "".join(f"{p},{digest(d)},{len(d)}\n" for p, (d, _) in files.items())
        + f"{info}/RECORD,,\n"
    )
    files[f"{info}/RECORD"] = (record.encode(), 0o644)
    path = Path(out) / f"{name}-{version}-py3-none-{tag}.whl"
    path.parent.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p, (data, mode) in files.items():
            entry = zipfile.ZipInfo(p, STAMP)
            entry.external_attr = (0o100000 | mode) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(entry, data)
    path.write_bytes(buf.getvalue())
    return path


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    print(main(*sys.argv[1:]))
