import json

import pytest
from cryptography import x509

from pki.lifecycle import CertificateManager, LifecycleError
from pki.models import CertMode, LifecycleState, ValidationReason
from pki.validation import validate_certificate

S = LifecycleState


def _validate(manager, mc, trust_store, intermediate_ca, cert=None):
    return validate_certificate(cert or mc.certificate, trust_store, [intermediate_ca.certificate],
                                crls=manager.current_crls())


@pytest.fixture
def manager():
    return CertificateManager()


def test_issue_goes_through_generate_issue_active(manager, intermediate_ca):
    mc = manager.issue(intermediate_ca, "rtu-12.example.test")
    assert mc.state is S.ACTIVE
    assert [h.to_state for h in mc.history] == [S.GENERATE, S.ISSUE, S.ACTIVE]
    assert mc.mode is CertMode.CLASSICAL
    assert manager.get(mc.cert_id) is mc


def test_status_is_json_for_the_platform(manager, intermediate_ca):
    mc = manager.issue(intermediate_ca, "rtu-13.example.test")
    data = json.loads(json.dumps(mc.to_dict()))
    assert data["cert_id"] == mc.cert_id
    assert data["state"] == "ACTIVE"
    assert data["mode"] == "classical"
    assert data["expired"] is False
    assert [h["to"] for h in data["history"]] == ["GENERATE", "ISSUE", "ACTIVE"]


def test_renew_keeps_key_and_supersedes_old_certificate(manager, intermediate_ca, trust_store):
    mc = manager.issue(intermediate_ca, "plc-1.example.test")
    old_cert, old_key = mc.certificate, mc.private_key
    manager.renew(mc.cert_id)
    assert mc.state is S.ACTIVE
    assert mc.certificate.serial_number != old_cert.serial_number
    assert mc.private_key is old_key
    assert mc.previous_serials == [f"{old_cert.serial_number:x}"]
    assert [h.to_state for h in mc.history][-2:] == [S.RENEW, S.ACTIVE]
    assert _validate(manager, mc, trust_store, intermediate_ca).valid
    old = _validate(manager, mc, trust_store, intermediate_ca, cert=old_cert)
    assert old.reason is ValidationReason.REVOKED and "superseded" in old.issues[0].message


def test_renew_without_revoking_previous(manager, intermediate_ca, trust_store):
    mc = manager.issue(intermediate_ca, "plc-2.example.test")
    old_cert = mc.certificate
    manager.renew(mc.cert_id, revoke_previous=False)
    assert _validate(manager, mc, trust_store, intermediate_ca, cert=old_cert).valid


def test_rotate_changes_key(manager, intermediate_ca):
    mc = manager.issue(intermediate_ca, "plc-3.example.test")
    old_numbers = mc.certificate.public_key().public_numbers()
    manager.rotate(mc.cert_id)
    assert mc.certificate.public_key().public_numbers() != old_numbers
    assert "rotate key" in mc.history[-1].note


def test_revoke(manager, intermediate_ca, trust_store):
    mc = manager.issue(intermediate_ca, "plc-4.example.test")
    manager.revoke(mc.cert_id, x509.ReasonFlags.key_compromise)
    assert mc.state is S.REVOKED
    assert [h.to_state for h in mc.history][-2:] == [S.REVOKE, S.REVOKED]
    assert _validate(manager, mc, trust_store, intermediate_ca).reason is ValidationReason.REVOKED


def test_revoked_certificate_cannot_be_renewed_or_revoked_again(manager, intermediate_ca):
    mc = manager.issue(intermediate_ca, "plc-5.example.test")
    manager.revoke(mc.cert_id)
    with pytest.raises(LifecycleError):
        manager.renew(mc.cert_id)
    with pytest.raises(LifecycleError):
        manager.revoke(mc.cert_id)


def test_invalid_transition_is_rejected(manager, intermediate_ca):
    mc = manager.issue(intermediate_ca, "plc-6.example.test")
    with pytest.raises(LifecycleError):
        mc._move(S.ISSUE)


def test_failed_renewal_returns_to_active(manager, intermediate_ca):
    mc = manager.issue(intermediate_ca, "plc-7.example.test")
    cert = mc.certificate
    with pytest.raises(ValueError):
        manager.migrate(mc.cert_id, CertMode.HYBRID)  # a classical CA cannot issue hybrid
    assert mc.state is S.ACTIVE
    assert mc.certificate is cert
    assert "failed" in mc.history[-1].note


def test_unknown_id(manager):
    with pytest.raises(LifecycleError):
        manager.get("nope")
