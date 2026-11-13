"""Certificate lifecycle: issue, renew, rotate, migrate and revoke.

A ManagedCertificate is one asset's credential. Its certificate is replaced
on renewal, but the record (and its ID) stays the same, so Person 3's
inventory can track one row per asset credential. States follow the spec:

    GENERATE -> ISSUE -> ACTIVE
    ACTIVE -> RENEW -> ACTIVE      (renew, rotate key, or migrate mode)
    ACTIVE -> REVOKE -> REVOKED

Renewing revokes the previous certificate with reason "superseded" by
default, so only the newest certificate validates.
"""
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from pki.ca import CertificateAuthority
from pki.issuance import issue_certificate
from pki.models import CertMode, LifecycleState
from pki.parsing import certificate_mode, parse_certificate
from pki.revocation import RevocationRegistry

S = LifecycleState
ALLOWED_TRANSITIONS: dict[LifecycleState, set[LifecycleState]] = {
    S.GENERATE: {S.ISSUE},
    S.ISSUE: {S.ACTIVE},
    S.ACTIVE: {S.RENEW, S.REVOKE},
    S.RENEW: {S.ACTIVE},
    S.REVOKE: {S.REVOKED},
    S.REVOKED: set(),
}


class LifecycleError(Exception):
    pass


@dataclass
class StateChange:
    from_state: LifecycleState | None
    to_state: LifecycleState
    at: datetime
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "from": self.from_state.value if self.from_state else None,
            "to": self.to_state.value,
            "at": self.at.isoformat(),
            "note": self.note,
        }


@dataclass
class ManagedCertificate:
    cert_id: str
    common_name: str
    dns_names: list[str]
    issuer: CertificateAuthority
    state: LifecycleState = S.GENERATE
    certificate: x509.Certificate | None = None
    private_key: Any = None
    previous_serials: list[str] = field(default_factory=list)
    history: list[StateChange] = field(default_factory=list)

    @property
    def mode(self) -> CertMode | None:
        return certificate_mode(self.certificate) if self.certificate else None

    def _move(self, to_state: LifecycleState, note: str = "") -> None:
        if to_state not in ALLOWED_TRANSITIONS[self.state]:
            raise LifecycleError(f"cannot go from {self.state.value} to {to_state.value}")
        self.history.append(StateChange(self.state, to_state, datetime.now(timezone.utc), note))
        self.state = to_state

    def to_dict(self, at_time: datetime | None = None) -> dict:
        """JSON-friendly status for the migration platform."""
        at_time = at_time or datetime.now(timezone.utc)
        record = parse_certificate(self.certificate).to_dict() if self.certificate else {}
        record.update({
            "cert_id": self.cert_id,
            "common_name": self.common_name,
            "state": self.state.value,
            "expired": bool(self.certificate and at_time > self.certificate.not_valid_after_utc),
            "previous_serials": self.previous_serials,
            "history": [h.to_dict() for h in self.history],
        })
        return record


class CertificateManager:
    """Issues and tracks managed certificates, and keeps each CA's revocation registry."""

    def __init__(self):
        self._certs: dict[str, ManagedCertificate] = {}
        self._registries: dict[bytes, RevocationRegistry] = {}

    # ---------- revocation registries ----------

    def registry_for(self, ca: CertificateAuthority) -> RevocationRegistry:
        key = ca.certificate.fingerprint(hashes.SHA256())
        if key not in self._registries:
            self._registries[key] = RevocationRegistry(ca)
        return self._registries[key]

    def current_crls(self) -> list[x509.CertificateRevocationList]:
        """A freshly signed CRL from every CA this manager has used."""
        return [r.generate_crl() for r in self._registries.values()]

    # ---------- lifecycle operations ----------

    def get(self, cert_id: str) -> ManagedCertificate:
        try:
            return self._certs[cert_id]
        except KeyError:
            raise LifecycleError(f"no certificate with id {cert_id}") from None

    def all(self) -> list[ManagedCertificate]:
        return list(self._certs.values())

    def issue(self, ca: CertificateAuthority, common_name: str, dns_names: list[str] | None = None,
              mode: CertMode | None = None, validity_days: int | None = None) -> ManagedCertificate:
        mc = ManagedCertificate(uuid.uuid4().hex[:12], common_name, dns_names or [common_name], ca)
        mc.history.append(StateChange(None, S.GENERATE, datetime.now(timezone.utc), "key pair requested"))
        issued = issue_certificate(ca, common_name, mc.dns_names, validity_days, mode=mode)
        mc.private_key = issued.private_key
        mc._move(S.ISSUE, f"issued by {ca.certificate.subject.rfc4514_string()}")
        mc.certificate = issued.certificate
        mc._move(S.ACTIVE, f"serial {issued.certificate.serial_number:x} ({mc.mode.value})")
        self.registry_for(ca)
        self._certs[mc.cert_id] = mc
        return mc

    def renew(self, cert_id: str, rotate_key: bool = False, revoke_previous: bool = True,
              mode: CertMode | None = None, ca: CertificateAuthority | None = None,
              validity_days: int | None = None) -> ManagedCertificate:
        """Replace the certificate, keeping the key unless rotating. A new mode always means a new key."""
        mc = self.get(cert_id)
        old_cert, old_issuer = mc.certificate, mc.issuer
        new_issuer = ca or mc.issuer
        target_mode = mode or mc.mode
        changes_mode = target_mode is not mc.mode
        rotate_key = rotate_key or changes_mode
        if changes_mode:
            action = f"migrate {mc.mode.value} -> {target_mode.value}"
        else:
            action = "rotate key" if rotate_key else "renew"

        mc._move(S.RENEW, action)
        try:
            issued = issue_certificate(new_issuer, mc.common_name, mc.dns_names, validity_days,
                                       mode=target_mode, private_key=None if rotate_key else mc.private_key)
        except Exception as e:
            mc._move(S.ACTIVE, f"{action} failed: {e}")
            raise
        if revoke_previous:
            self.registry_for(old_issuer).revoke(old_cert, x509.ReasonFlags.superseded)
        mc.previous_serials.append(f"{old_cert.serial_number:x}")
        mc.certificate, mc.private_key, mc.issuer = issued.certificate, issued.private_key, new_issuer
        self.registry_for(new_issuer)
        mc._move(S.ACTIVE, f"{action}: serial {old_cert.serial_number:x} -> {issued.certificate.serial_number:x}")
        return mc

    def rotate(self, cert_id: str, **kwargs) -> ManagedCertificate:
        return self.renew(cert_id, rotate_key=True, **kwargs)

    def migrate(self, cert_id: str, mode: CertMode, ca: CertificateAuthority | None = None) -> ManagedCertificate:
        """Migration-aware PKI: reissue an asset's credential in a new mode (e.g. classical -> hybrid)."""
        return self.renew(cert_id, mode=mode, ca=ca)

    def revoke(self, cert_id: str, reason: x509.ReasonFlags = x509.ReasonFlags.unspecified) -> ManagedCertificate:
        mc = self.get(cert_id)
        mc._move(S.REVOKE, reason.value)
        self.registry_for(mc.issuer).revoke(mc.certificate, reason)
        mc._move(S.REVOKED, f"serial {mc.certificate.serial_number:x} added to CRL")
        return mc
