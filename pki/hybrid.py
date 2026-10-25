"""Hybrid (RSA + ML-DSA) certificate encoding.

DEFAULT (confirm with Poojita, open question 1): a hybrid certificate is an
ordinary RSA certificate that also carries three non-critical extensions,
modelled on the "alternative signature" extensions of ITU-T X.509 (2019):

    subjectAltPublicKeyInfo (2.5.29.72)  the subject's ML-DSA public key
    altSignatureAlgorithm   (2.5.29.73)  the issuer's ML-DSA algorithm
    altSignatureValue       (2.5.29.74)  the issuer's ML-DSA signature

The ML-DSA signature covers the "pre-TBS": the to-be-signed certificate with
the altSignatureValue extension removed. The RSA signature then covers the
whole certificate, including the ML-DSA signature, so stripping the PQ part
breaks the RSA signature. Legacy RSA-only software ignores the non-critical
extensions and still reads the certificate.

This is a prototype encoding. It is not claimed to be a new standard and has
not been tested for interoperability with other implementations.
"""
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, rsa
from cryptography.x509.oid import ObjectIdentifier

ALT_PUBLIC_KEY_OID = ObjectIdentifier("2.5.29.72")
ALT_SIGNATURE_ALGORITHM_OID = ObjectIdentifier("2.5.29.73")
ALT_SIGNATURE_VALUE_OID = ObjectIdentifier("2.5.29.74")

ML_DSA_KEY_CLASSES = {
    "ML-DSA-44": mldsa.MLDSA44PrivateKey,
    "ML-DSA-65": mldsa.MLDSA65PrivateKey,
    "ML-DSA-87": mldsa.MLDSA87PrivateKey,
}
ML_DSA_PUBLIC_TYPES = (mldsa.MLDSA44PublicKey, mldsa.MLDSA65PublicKey, mldsa.MLDSA87PublicKey)
ML_DSA_PRIVATE_TYPES = tuple(ML_DSA_KEY_CLASSES.values())
ML_DSA_SIGNATURE_OIDS = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}


@dataclass(frozen=True)
class HybridPrivateKey:
    """The two private keys behind a hybrid identity."""
    classical: rsa.RSAPrivateKey
    pq: Any  # an ML-DSA private key


def generate_ml_dsa_key(algorithm: str) -> Any:
    try:
        return ML_DSA_KEY_CLASSES[algorithm].generate()
    except KeyError:
        raise ValueError(f"unknown PQ algorithm {algorithm!r}") from None


def ml_dsa_name(key: Any) -> str:
    """'ML-DSA-65' for an ML-DSA public or private key."""
    return type(key).__name__.replace("MLDSA", "ML-DSA-").replace("PublicKey", "").replace("PrivateKey", "")


# ---------- minimal DER helpers (just enough to edit a TBSCertificate) ----------

def _read_tlv(data: bytes, i: int) -> tuple[int, int, int]:
    """Return (tag, content_start, end) of the DER element starting at data[i]."""
    tag, first = data[i], data[i + 1]
    if first < 0x80:
        return tag, i + 2, i + 2 + first
    n = first & 0x7F
    length = int.from_bytes(data[i + 2:i + 2 + n], "big")
    return tag, i + 2 + n, i + 2 + n + length


def _children(content: bytes) -> list[bytes]:
    """Split the content of a constructed DER element into its raw child elements."""
    out, i = [], 0
    while i < len(content):
        _, _, end = _read_tlv(content, i)
        out.append(content[i:end])
        i = end
    return out


def _tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content


def _content(element: bytes) -> bytes:
    _, start, end = _read_tlv(element, 0)
    return element[start:end]


_ALT_SIGNATURE_VALUE_DER_OID = _tlv(0x06, bytes([0x55, 0x1D, 0x4A]))  # 2.5.29.74


def pre_tbs_bytes(cert: x509.Certificate) -> bytes:
    """The TBSCertificate without the altSignatureValue extension (what ML-DSA signs)."""
    tbs = cert.tbs_certificate_bytes
    fields = _children(_content(tbs))
    rebuilt = []
    for f in fields:
        if f[0] == 0xA3:  # [3] EXPLICIT Extensions
            extensions = _children(_content(_content(f)))
            kept = [e for e in extensions if _children(_content(e))[0] != _ALT_SIGNATURE_VALUE_DER_OID]
            f = _tlv(0xA3, _tlv(0x30, b"".join(kept)))
        rebuilt.append(f)
    return _tlv(0x30, b"".join(rebuilt))


# ---------- building the extensions ----------

def spki_der(public_key: Any) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def alt_public_key_extension(pq_public_key: Any) -> x509.UnrecognizedExtension:
    return x509.UnrecognizedExtension(ALT_PUBLIC_KEY_OID, spki_der(pq_public_key))


def alt_signature_algorithm_extension(pq_public_key: Any) -> x509.UnrecognizedExtension:
    algorithm_identifier = _children(_content(spki_der(pq_public_key)))[0]
    return x509.UnrecognizedExtension(ALT_SIGNATURE_ALGORITHM_OID, algorithm_identifier)


def alt_signature_value_extension(signature: bytes) -> x509.UnrecognizedExtension:
    return x509.UnrecognizedExtension(ALT_SIGNATURE_VALUE_OID, _tlv(0x03, b"\x00" + signature))


# ---------- reading them back ----------

def _extension_bytes(cert: x509.Certificate, oid: ObjectIdentifier) -> bytes | None:
    try:
        return cert.extensions.get_extension_for_oid(oid).value.value
    except x509.ExtensionNotFound:
        return None


def alt_public_key(cert: x509.Certificate) -> Any | None:
    """The subject's ML-DSA public key carried in a hybrid certificate, if any."""
    der = _extension_bytes(cert, ALT_PUBLIC_KEY_OID)
    return serialization.load_der_public_key(der) if der else None


def alt_signature(cert: x509.Certificate) -> bytes | None:
    der = _extension_bytes(cert, ALT_SIGNATURE_VALUE_OID)
    return _content(der)[1:] if der else None  # drop the BIT STRING unused-bits byte


def alt_signature_algorithm(cert: x509.Certificate) -> bytes | None:
    return _extension_bytes(cert, ALT_SIGNATURE_ALGORITHM_OID)


def _decode_oid(element: bytes) -> str:
    body = _content(element)
    parts = [body[0] // 40, body[0] % 40]
    value = 0
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(map(str, parts))


def alt_signature_algorithm_name(cert: x509.Certificate) -> str | None:
    """'ML-DSA-65' for a hybrid certificate's ML-DSA signature, else None."""
    algorithm_identifier = alt_signature_algorithm(cert)
    if algorithm_identifier is None:
        return None
    oid = _decode_oid(_children(_content(algorithm_identifier))[0])
    return ML_DSA_SIGNATURE_OIDS.get(oid, oid)


def pq_public_key(cert: x509.Certificate) -> Any | None:
    """The ML-DSA key a certificate's subject signs with: its main key (PQ mode) or its alt key (hybrid)."""
    key = cert.public_key()
    if isinstance(key, ML_DSA_PUBLIC_TYPES):
        return key
    return alt_public_key(cert)


def is_hybrid(cert: x509.Certificate) -> bool:
    return alt_public_key(cert) is not None
