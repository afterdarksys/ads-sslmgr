"""Certificate validation and safe filesystem installation helpers."""

import os
import re
import tempfile
from pathlib import Path
from typing import Tuple

from cryptography import x509


_PEM_CERT = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


def parse_pem_bundle(value: str) -> Tuple[str, str, x509.Certificate]:
    blocks = _PEM_CERT.findall(value or "")
    if not blocks:
        raise ValueError("Provider response did not contain a PEM certificate")
    certificates = []
    for block in blocks:
        certificates.append(x509.load_pem_x509_certificate((block + "\n").encode()))
    leaf = blocks[0].strip() + "\n"
    chain = "\n".join(block.strip() for block in blocks[1:])
    if chain:
        chain += "\n"
    return leaf, chain, certificates[0]


def atomic_write_certificate(path, certificate_pem: str) -> str:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix="." + target.name, suffix=".tmp", dir=str(target.parent))
    try:
        with os.fdopen(descriptor, "w") as handle:
            handle.write(certificate_pem)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return str(target)
