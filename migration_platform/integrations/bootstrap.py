"""Connects the real crypto layer (Person 1) and PKI (Person 2) to the platform.

This is the single place where the three workstreams meet:

    crypto_agility registry  ->  CryptoAdapter  ->  /algorithms, recommendations
    pki CertificateManager   ->  PKIAdapter     ->  /certificates

Call ``connect()`` once at startup (main.py does).
"""
import os
from dataclasses import dataclass, field
from functools import partial

from crypto_agility.migration_logic import (
    CryptoCapabilityCatalog,
    TransitionOptions,
    measure_algorithms,
)
from crypto_agility.policies import create_default_registry
from migration_platform.integrations.crypto_adapter import CryptoAdapter
from migration_platform.integrations.pki_adapter import PKIAdapter
from pki.ca import CertificateAuthority, create_intermediate_ca, create_root_ca
from pki.config import PKIConfig
from pki.lifecycle import CertificateManager
from pki.models import CertMode
from pki.trust import TrustStore
from pki.validation import validate_certificate


def build_crypto_adapter(registry=None) -> CryptoAdapter:
    registry = registry or create_default_registry()
    return CryptoAdapter(
        capability_catalog=CryptoCapabilityCatalog(registry),
        transition_options=TransitionOptions(registry),
        performance_measure_function=partial(measure_algorithms, registry),
    )


@dataclass
class PKIContext:
    """A hybrid Root -> Intermediate hierarchy plus the manager of asset certificates."""
    root: CertificateAuthority
    intermediate: CertificateAuthority
    manager: CertificateManager = field(default_factory=CertificateManager)

    @property
    def trust_store(self) -> TrustStore:
        return TrustStore([self.root.certificate])

    def validate(self, certificate, trust_context=None):
        return validate_certificate(
            certificate,
            self.trust_store,
            [self.intermediate.certificate],
            crls=self.manager.current_crls(),
        )


def build_pki_context(config: PKIConfig | None = None) -> PKIContext:
    # A hybrid hierarchy can issue classical, hybrid and PQ certificates.
    config = config or PKIConfig(
        mode=CertMode.HYBRID,
        rsa_key_size=int(os.environ.get("JANUS_RSA_KEY_SIZE", "4096")),
    )
    root = create_root_ca("Janus Root CA", config)
    intermediate = create_intermediate_ca(root, "Janus Intermediate CA")
    return PKIContext(root, intermediate)


def build_pki_adapter(context: PKIContext) -> PKIAdapter:
    return PKIAdapter(
        certificate_manager=context.manager,
        validation_function=context.validate,
        trust_context_provider=lambda managed_certificate: None,
    )


def connect(crypto_adapter: CryptoAdapter | None = None, pki_context: PKIContext | None = None):
    """Register the adapters with the API routers."""
    from migration_platform.api import algorithms, certificates

    crypto_adapter = crypto_adapter or build_crypto_adapter()
    pki_context = pki_context or build_pki_context()
    algorithms.configure_crypto_adapter(crypto_adapter)
    certificates.configure_pki(pki_context, build_pki_adapter(pki_context))
    return crypto_adapter, pki_context
