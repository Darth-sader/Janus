"""Phase 4: migration-logic surface for the migration platform
(capability catalog, transition modes, performance metrics)."""

from __future__ import annotations

import pytest

from crypto.errors import UnsupportedAlgorithmError
from crypto_agility.migration_logic import (
    CryptoCapabilityCatalog,
    MigrationMode,
    TransitionOptions,
    measure_algorithms,
    measure_provider,
)
from crypto_agility.policies import CryptoConfiguration, CryptoMode, ProviderSelector, create_default_registry


@pytest.fixture(scope="module")
def registry():
    return create_default_registry()


@pytest.fixture(scope="module")
def catalog(registry):
    return CryptoCapabilityCatalog(registry)


@pytest.fixture(scope="module")
def transitions(registry):
    return TransitionOptions(registry)


# --------------------------------------------------------------------- #
# capability catalog
# --------------------------------------------------------------------- #
def test_available_algorithms_match_pqcalgorithm_entity(catalog):
    records = catalog.available_algorithms()
    ids = {r["algorithm_id"] for r in records}
    assert {"rsa4096", "mldsa65", "RSA4096-MLDSA"} <= ids
    for record in records:
        # PQCAlgorithm fields from the spec's data model must be present
        for field in ("name", "family", "standard", "security_level", "key_size", "signature_size", "implementation"):
            assert field in record, field


def test_algorithm_details_for_implemented_and_candidate(catalog):
    mldsa = catalog.algorithm_details("mldsa65")
    assert mldsa["implemented"] is True
    assert mldsa["quantum_vulnerable"] is False
    assert mldsa["key_size"] == 1952

    rsa = catalog.algorithm_details("rsa4096")
    assert rsa["quantum_vulnerable"] is True
    assert rsa["family"] == "classical"

    picnic = catalog.algorithm_details("picnic")
    assert picnic["implemented"] is False


def test_unknown_algorithm_details_raise(catalog):
    with pytest.raises(UnsupportedAlgorithmError):
        catalog.algorithm_details("rsa-2048-classic")


def test_availability_reporting(catalog):
    assert catalog.is_available("mldsa65") is True
    assert catalog.is_available("picnic") is False

    ok = catalog.check_availability("mldsa65")
    assert ok == {"algorithm_id": "mldsa65", "available": True, "reason": ok["reason"]}

    candidate = catalog.check_availability("picnic")
    assert candidate["available"] is False
    assert "candidate" in candidate["reason"]

    unknown = catalog.check_availability("mldsa99")
    assert unknown["available"] is False
    assert "unknown algorithm" in unknown["reason"]


def test_unsupported_candidates_are_listed_explicitly(catalog):
    candidates = catalog.unavailable_candidates()
    ids = {c["algorithm_id"] for c in candidates}
    assert "picnic" in ids
    for candidate in candidates:
        assert candidate["implemented"] is False
        assert candidate["availability_reason"]


def test_capability_report_is_json_serializable(catalog):
    import json

    report = catalog.capability_report()
    assert json.loads(json.dumps(report)) == report
    assert {"implemented", "candidates", "mode_support", "generated_at"} <= set(report)
    assert report["mode_support"] == {"classical": True, "pq": True, "hybrid": True}


# --------------------------------------------------------------------- #
# transition modes
# --------------------------------------------------------------------- #
def test_all_three_modes_supported(transitions):
    assert transitions.supported_modes() == ["classical", "hybrid", "pq"]


def test_mode_requirements_are_documented(transitions):
    reqs = transitions.mode_requirements(MigrationMode.HYBRID)
    assert reqs["required_families"] == ["classical", "pq", "hybrid"]
    assert "RSA4096-MLDSA" in reqs["default_algorithm_ids"]


def test_feasibility_is_structured_and_explainable(transitions):
    result = transitions.check_mode("hybrid")
    d = result.to_dict()
    assert d["supported"] is True
    assert d["blockers"] == []
    assert "hybrid" in d["explanation"]


def test_algorithm_for_mode_family_mismatch(transitions):
    ok = transitions.check_algorithm_for_mode("pq", "mldsa87")
    assert ok.supported is True
    bad = transitions.check_algorithm_for_mode("pq", "rsa4096")
    assert bad.supported is False
    assert bad.blockers and "family" in bad.explanation


def test_candidate_cannot_serve_a_mode(transitions):
    result = transitions.check_algorithm_for_mode("pq", "picnic")
    assert result.supported is False
    assert any("candidate" in b for b in result.blockers)


def test_unknown_algorithm_for_mode(transitions):
    result = transitions.check_algorithm_for_mode("pq", "falcon512")
    assert result.supported is False
    assert any("not registered" in b for b in result.blockers)


# --------------------------------------------------------------------- #
# performance metrics
# --------------------------------------------------------------------- #
def test_measure_provider_mldsa(mldsa_provider):
    profile = measure_provider(mldsa_provider, iterations=3).to_dict()
    assert profile["algorithm_id"] == "mldsa65"
    assert profile["public_key_bytes"] == 1952
    assert profile["signature_bytes"] == 3309
    assert profile["sign_ms"] > 0 and profile["verify_ms"] > 0
    assert profile["keygen_ms"] > 0


def test_measure_provider_can_skip_keygen(mldsa_provider):
    profile = measure_provider(mldsa_provider, iterations=2, include_keygen=False)
    assert profile.keygen_ms == -1.0
    assert "keygen not measured" in profile.notes


def test_measure_algorithms_via_registry(registry):
    profiles = measure_algorithms(registry, ["mldsa65", "RSA4096-MLDSA"], iterations=2)
    assert set(profiles) == {"mldsa65", "RSA4096-MLDSA"}
    assert profiles["mldsa65"]["sign_ms"] > 0


def test_measure_unknown_algorithm_raises(registry):
    with pytest.raises(UnsupportedAlgorithmError):
        measure_algorithms(registry, ["falcon512"])


# --------------------------------------------------------------------- #
# selector + catalog work together (the platform's actual call pattern)
# --------------------------------------------------------------------- #
def test_platform_call_pattern(registry, catalog, transitions, message):
    # 1. platform asks what is available
    available = {r["algorithm_id"] for r in catalog.available_algorithms()}
    # 2. platform asks whether the hybrid target mode is feasible
    assert transitions.check_mode("hybrid").supported is True
    # 3. platform selects a provider through explicit configuration
    selector = ProviderSelector(registry, CryptoConfiguration(CryptoMode.HYBRID))
    assert selector.signing_algorithm_id() in available
    # 4. selected provider actually signs/verifies
    provider = selector.provider()
    kp = provider.generate_keypair()
    assert provider.verify(message, provider.sign(message, kp.private_key), kp.public_key)
