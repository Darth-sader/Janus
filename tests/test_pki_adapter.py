import pytest

from migration_platform.integrations.pki_adapter import PKIAdapter


class MockCertificate:

    def __init__(self):
        self.cert_id = "cert-001"
        self.certificate = "mock-certificate"

    def to_dict(self):
        return {
            "cert_id": self.cert_id,
            "state": "ACTIVE",
        }


class MockCertificateManager:

    def __init__(self):
        self.certificate = MockCertificate()

    def get(self, cert_id):
        if cert_id == "cert-001":
            return self.certificate
        return None

    def all(self):
        return [self.certificate]

    def migrate(self, cert_id, mode):
        return self.certificate


class MockValidationResult:

    def to_dict(self):
        return {
            "valid": True,
            "reason": "Certificate is valid",
            "issues": [],
        }


def mock_validation(certificate, trust_context):
    assert certificate == "mock-certificate"
    assert trust_context == "mock-trust-context"
    return MockValidationResult()


def mock_trust_context(certificate):
    return "mock-trust-context"


def test_get_certificate():
    adapter = PKIAdapter(MockCertificateManager())

    result = adapter.get_certificate("cert-001")

    assert result["cert_id"] == "cert-001"
    assert result["state"] == "ACTIVE"


def test_list_certificates():
    adapter = PKIAdapter(MockCertificateManager())

    result = adapter.list_certificates()

    assert len(result) == 1
    assert result[0]["cert_id"] == "cert-001"


def test_validate_certificate():
    adapter = PKIAdapter(
        MockCertificateManager(),
        mock_validation,
        mock_trust_context,
    )

    result = adapter.validate_certificate("cert-001")

    assert result["valid"] is True


def test_migration_requires_approval():
    adapter = PKIAdapter(MockCertificateManager())

    with pytest.raises(PermissionError):
        adapter.migrate_certificate(
            "cert-001",
            "hybrid",
        )


def test_migration_with_approval():
    adapter = PKIAdapter(MockCertificateManager())

    result = adapter.migrate_certificate(
        "cert-001",
        "hybrid",
        approved=True,
    )

    assert result["cert_id"] == "cert-001"


def test_missing_certificate():
    adapter = PKIAdapter(MockCertificateManager())

    with pytest.raises(ValueError):
        adapter.get_certificate("unknown-cert")