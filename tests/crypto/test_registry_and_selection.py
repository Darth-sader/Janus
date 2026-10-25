"""Phase 4: algorithm registry + provider selection (no-silent-fallback
rules, candidate handling, mode selection, explainability)."""

from __future__ import annotations

import pytest

from crypto import MLDSAProvider, RSA4096Provider, SLHDSAProvider
from crypto.errors import ConfigurationError, ProviderUnavailableError, UnsupportedAlgorithmError
from crypto.hybrid import HybridCryptoProvider
from crypto_agility.policies import (
    AlgorithmRegistry,
    CryptoConfiguration,
    CryptoMode,
    ProviderSelector,
    create_default_registry,
)


@pytest.fixture(scope="module")
def registry():
    return create_default_registry()


# --------------------------------------------------------------------- #
# registration and lookup
# --------------------------------------------------------------------- #
def test_default_registry_contains_expected_algorithms(registry):
    ids = {e.algorithm_id for e in registry.list_algorithms()}
    assert {"rsa4096", "mldsa44", "mldsa65", "mldsa87", "slhdsa-sha2-128s", "RSA4096-MLDSA"} <= ids


def test_primary_configuration_is_implemented(registry):
    for algorithm_id in ("rsa4096", "mldsa65", "RSA4096-MLDSA"):
        assert registry.is_available(algorithm_id), algorithm_id
        assert isinstance(registry.get_provider(algorithm_id), object)


def test_unknown_algorithm_raises_without_fallback(registry):
    with pytest.raises(UnsupportedAlgorithmError):
        registry.get_provider("rsa2048")
    with pytest.raises(UnsupportedAlgorithmError):
        registry.get_provider("mldsa99")


def test_candidate_without_provider_is_reported(registry):
    entry = registry.get("picnic")
    assert entry.implemented is False
    assert entry.provider is None
    with pytest.raises(ProviderUnavailableError):
        registry.get_provider("picnic")
    assert registry.is_available("picnic") is False


def test_duplicate_registration_rejected(registry):
    with pytest.raises(ConfigurationError):
        registry.register_provider(RSA4096Provider())


def test_register_new_provider_extends_registry_without_code_changes():
    # agility: a new PQ parameter set is one registration away
    custom = AlgorithmRegistry()
    custom.register_provider(RSA4096Provider())
    custom.register_provider(MLDSAProvider("mldsa87"))
    assert custom.is_available("mldsa87")
    assert not custom.is_available("mldsa65")  # and nothing silently appears


def test_registry_lists_operations_via_capabilities(registry):
    caps = registry.capabilities("mldsa65")
    assert "keygen" in caps.supported_operations
    assert "sign" in caps.supported_operations
    assert "verify" in caps.supported_operations


def test_aliases_resolve_to_canonical_ids(registry):
    assert registry.get("hybrid").algorithm_id == "RSA4096-MLDSA"
    assert registry.get("slhdsa").algorithm_id == "slhdsa-sha2-128s"


# --------------------------------------------------------------------- #
# provider selection
# --------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("mode", "expected_id"),
    [
        (CryptoMode.CLASSICAL, "rsa4096"),
        (CryptoMode.PQ, "mldsa65"),
        (CryptoMode.HYBRID, "RSA4096-MLDSA"),
    ],
)
def test_select_each_mode(registry, mode, expected_id):
    selector = ProviderSelector(registry, CryptoConfiguration(mode))
    assert selector.signing_algorithm_id() == expected_id
    provider = selector.provider()
    assert provider.algorithm_id == expected_id


def test_selection_is_deterministic(registry):
    a = ProviderSelector(registry, CryptoConfiguration(CryptoMode.HYBRID)).describe().to_dict()
    b = ProviderSelector(registry, CryptoConfiguration(CryptoMode.HYBRID)).describe().to_dict()
    assert a == b


def test_hybrid_mode_supports_generic_interface(registry, message):
    provider = ProviderSelector(registry, CryptoConfiguration(CryptoMode.HYBRID)).provider()
    assert isinstance(provider, HybridCryptoProvider)
    kp = provider.generate_keypair()
    sig = provider.sign(message, kp.private_key)
    assert provider.verify(message, sig, kp.public_key)


def test_custom_configuration_selects_other_parameter_set(registry):
    selector = ProviderSelector(registry, CryptoConfiguration(CryptoMode.PQ, pq_algorithm="mldsa87"))
    assert selector.signing_algorithm_id() == "mldsa87"


def test_unknown_mode_rejected(registry):
    with pytest.raises(ConfigurationError):
        CryptoConfiguration("quantum")


def test_unknown_algorithm_in_configuration_rejected(registry):
    with pytest.raises(ConfigurationError):
        ProviderSelector(registry, CryptoConfiguration(CryptoMode.PQ, pq_algorithm="mldsa99"))


def test_candidate_cannot_be_selected(registry):
    with pytest.raises(ConfigurationError):
        ProviderSelector(registry, CryptoConfiguration(CryptoMode.PQ, pq_algorithm="picnic"))


def test_family_mismatch_rejected(registry):
    with pytest.raises(ConfigurationError):
        ProviderSelector(registry, CryptoConfiguration(CryptoMode.PQ, pq_algorithm="rsa4096"))


def test_verification_provider_is_exact_no_fallback(registry):
    selector = ProviderSelector(registry, CryptoConfiguration(CryptoMode.HYBRID))
    assert selector.verification_provider_for("RSA4096-MLDSA").algorithm_id == "RSA4096-MLDSA"
    assert selector.is_compatible_with("RSA4096-MLDSA")
    assert not selector.is_compatible_with("rsa4096")
    with pytest.raises(UnsupportedAlgorithmError):
        selector.verification_provider_for("mldsa44-does-not-exist")


def test_describe_is_explainable(registry):
    decision = ProviderSelector(registry, CryptoConfiguration(CryptoMode.HYBRID)).describe()
    d = decision.to_dict()
    assert d["mode"] == "hybrid"
    assert d["algorithm_id"] == "RSA4096-MLDSA"
    assert "hybrid_algorithm=RSA4096-MLDSA" in d["requirements_met"]
