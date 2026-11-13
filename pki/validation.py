"""Certificate chain validation with a detailed, dashboard-friendly result.

Checks, in order: chain building and signatures, trust anchor, validity
periods, CA constraints, revocation (CRLs) and policy. Every problem found is
reported, not only the first, so the dashboard can show the full picture.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from cryptography import x509

from pki.models import ValidationIssue, ValidationReason, ValidationResult
from pki.parsing import certificate_mode
from pki.signatures import SignatureError, has_pq_signature, verify_signatures
from pki.trust import TrustStore


@dataclass(frozen=True)
class ValidationPolicy:
    require_pq: bool = False                # every certificate in the chain needs an ML-DSA signature
    require_revocation_check: bool = False  # a fresh, valid CRL must exist for every issuer
    max_chain_length: int = 5


def _subject(cert: x509.Certificate) -> str:
    return cert.subject.rfc4514_string()


def _is_self_issued(cert: x509.Certificate) -> bool:
    return cert.subject == cert.issuer


def _build_chain(cert, intermediates, trust_store, policy, issues) -> list[x509.Certificate]:
    """Walk from `cert` up to a self-issued certificate, verifying each signature."""
    pool = list(intermediates) + trust_store.roots
    chain = [cert]
    current = cert
    while not _is_self_issued(current):
        if len(chain) >= policy.max_chain_length:
            issues.append(ValidationIssue(ValidationReason.BAD_CHAIN, _subject(current), "chain is too long"))
            break
        candidates = [c for c in pool if c.subject == current.issuer and c not in chain]
        if not candidates:
            issues.append(ValidationIssue(ValidationReason.BAD_CHAIN, _subject(current),
                                          f"issuer {current.issuer.rfc4514_string()} not found"))
            break
        issuer, error = None, None
        for candidate in candidates:
            try:
                verify_signatures(current, candidate)
                issuer = candidate
                break
            except SignatureError as e:
                error = error or e
        if issuer is None:
            issues.append(ValidationIssue(error.reason, _subject(current), str(error)))
            issuer = candidates[0]  # keep walking so trust and expiry are still reported
        chain.append(issuer)
        current = issuer
    return chain


def _check_trust_anchor(chain, trust_store, issues) -> None:
    root = chain[-1]
    if not _is_self_issued(root):
        return  # incomplete chain, already reported
    try:
        verify_signatures(root, root)
    except SignatureError as e:
        issues.append(ValidationIssue(e.reason, _subject(root), f"root self-signature: {e}"))
    if not trust_store.is_trusted(root):
        issues.append(ValidationIssue(ValidationReason.UNTRUSTED_ROOT, _subject(root),
                                      "root certificate is not in the trust store"))


def _check_validity(chain, at_time, issues) -> None:
    for cert in chain:
        if at_time < cert.not_valid_before_utc:
            issues.append(ValidationIssue(ValidationReason.NOT_YET_VALID, _subject(cert),
                                          f"valid from {cert.not_valid_before_utc.isoformat()}"))
        elif at_time > cert.not_valid_after_utc:
            issues.append(ValidationIssue(ValidationReason.EXPIRED, _subject(cert),
                                          f"expired on {cert.not_valid_after_utc.isoformat()}"))


def _check_ca_constraints(chain, issues) -> None:
    # chain[i] for i >= 1 issued chain[i - 1]; (i - 1) CA certificates sit below it.
    for i, issuer in enumerate(chain[1:], start=1):
        try:
            bc = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            bc = None
        if bc is None or not bc.ca:
            issues.append(ValidationIssue(ValidationReason.BAD_CHAIN, _subject(issuer),
                                          "issuer is not a CA certificate"))
            continue
        try:
            if not issuer.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
                issues.append(ValidationIssue(ValidationReason.BAD_CHAIN, _subject(issuer),
                                              "issuer is not allowed to sign certificates"))
        except x509.ExtensionNotFound:
            pass
        if bc.path_length is not None and i - 1 > bc.path_length:
            issues.append(ValidationIssue(ValidationReason.BAD_CHAIN, _subject(issuer),
                                          f"path length {bc.path_length} exceeded"))


def _usable_crl(issuer, crls, at_time) -> tuple[x509.CertificateRevocationList | None, str]:
    problem = "no CRL for this issuer"
    for crl in crls:
        if crl.issuer != issuer.subject:
            continue
        if not crl.is_signature_valid(issuer.public_key()):
            problem = "CRL signature is invalid"
            continue
        if crl.next_update_utc is not None and at_time > crl.next_update_utc:
            problem = "CRL has expired"
            continue
        return crl, ""
    return None, problem


def _check_revocation(chain, crls, at_time, policy, issues) -> None:
    for cert, issuer in zip(chain, chain[1:]):
        crl, problem = _usable_crl(issuer, crls, at_time)
        if crl is None:
            if policy.require_revocation_check:
                issues.append(ValidationIssue(ValidationReason.REVOCATION_UNKNOWN, _subject(cert), problem))
            continue
        revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        if revoked is not None and revoked.revocation_date_utc <= at_time:
            try:
                reason = revoked.extensions.get_extension_for_class(x509.CRLReason).value.reason.value
            except x509.ExtensionNotFound:
                reason = "unspecified"
            issues.append(ValidationIssue(ValidationReason.REVOKED, _subject(cert),
                                          f"revoked on {revoked.revocation_date_utc.isoformat()} ({reason})"))


def _check_policy(chain, policy, issues) -> None:
    if policy.require_pq:
        for cert in chain:
            if not has_pq_signature(cert):
                issues.append(ValidationIssue(ValidationReason.POLICY_VIOLATION, _subject(cert),
                                              "post-quantum signature required, certificate is classical"))


def validate_certificate(
    cert: x509.Certificate,
    trust_store: TrustStore,
    intermediates: Iterable[x509.Certificate] = (),
    crls: Iterable[x509.CertificateRevocationList] = (),
    at_time: datetime | None = None,
    policy: ValidationPolicy = ValidationPolicy(),
) -> ValidationResult:
    at_time = at_time or datetime.now(timezone.utc)
    crls = list(crls)
    issues: list[ValidationIssue] = []

    chain = _build_chain(cert, intermediates, trust_store, policy, issues)
    _check_trust_anchor(chain, trust_store, issues)
    _check_validity(chain, at_time, issues)
    _check_ca_constraints(chain, issues)
    _check_revocation(chain, crls, at_time, policy, issues)
    _check_policy(chain, policy, issues)

    return ValidationResult(
        valid=not issues,
        reason=issues[0].reason if issues else ValidationReason.OK,
        issues=issues,
        chain=[_subject(c) for c in chain],
        mode=certificate_mode(cert),
        checked_at=at_time,
    )
