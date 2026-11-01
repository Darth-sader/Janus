from typing import Any, Callable

from migration_platform.integrations.contracts import (
    CertificateInfo,
    CertificateValidation,
)


class PKIAdapter:
    """
    Adapter connecting Person 3's migration platform
    with Person 2's PKI certificate lifecycle module.
    """

    def __init__(
        self,
        certificate_manager: Any,
        validation_function: Callable | None = None,
        trust_context_provider: Callable | None = None,
    ):
        self.manager = certificate_manager
        self.validation_function = validation_function
        self.trust_context_provider = trust_context_provider

    def get_certificate(self, cert_id: str) -> dict[str, Any]:
        certificate = self.manager.get(cert_id)

        if certificate is None:
            raise ValueError(f"Certificate not found: {cert_id}")

        return certificate.to_dict()

    def list_certificates(self) -> list[dict[str, Any]]:
        return [
            certificate.to_dict()
            for certificate in self.manager.all()
        ]

    def validate_certificate(self, cert_id: str) -> dict[str, Any]:
        if self.validation_function is None:
            raise RuntimeError("Certificate validation is not configured")

        if self.trust_context_provider is None:
            raise RuntimeError("Trust context provider is not configured")

        managed_certificate = self.manager.get(cert_id)

        if managed_certificate is None:
            raise ValueError(f"Certificate not found: {cert_id}")

        trust_context = self.trust_context_provider(
            managed_certificate
        )

        result = self.validation_function(
            managed_certificate.certificate,
            trust_context,
        )

        return result.to_dict()

    def migrate_certificate(
        self,
        cert_id: str,
        target_mode: str,
        approved: bool = False,
    ) -> dict[str, Any]:

        if not approved:
            raise PermissionError(
                "Human approval is required before certificate migration"
            )

        managed_certificate = self.manager.get(cert_id)

        if managed_certificate is None:
            raise ValueError(f"Certificate not found: {cert_id}")

        result = self.manager.migrate(
            cert_id,
            target_mode,
        )

        return result.to_dict()