"""Trust management: the set of root certificates we accept as trust anchors."""
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from pki.signatures import SignatureError, verify_signatures


def _fingerprint(cert: x509.Certificate) -> bytes:
    return cert.fingerprint(hashes.SHA256())


class TrustStore:
    def __init__(self, roots: list[x509.Certificate] | None = None):
        self._roots: dict[bytes, x509.Certificate] = {}
        for root in roots or []:
            self.add(root)

    def add(self, cert: x509.Certificate) -> None:
        """Trust a root. It must be a self-signed CA certificate."""
        if cert.subject != cert.issuer:
            raise ValueError("only self-signed root certificates can be trust anchors")
        try:
            is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except x509.ExtensionNotFound:
            is_ca = False
        if not is_ca:
            raise ValueError("trust anchor is not a CA certificate")
        try:
            verify_signatures(cert, cert)
        except SignatureError as e:
            raise ValueError(f"trust anchor's self-signature is invalid: {e}") from None
        self._roots[_fingerprint(cert)] = cert

    def remove(self, cert: x509.Certificate) -> None:
        self._roots.pop(_fingerprint(cert), None)

    def is_trusted(self, cert: x509.Certificate) -> bool:
        return _fingerprint(cert) in self._roots

    @property
    def roots(self) -> list[x509.Certificate]:
        return list(self._roots.values())

    def __len__(self) -> int:
        return len(self._roots)
