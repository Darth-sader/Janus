"""Shared fixtures.  RSA-4096 key generation takes seconds, so provider
instances and key pairs are session-scoped and reused across tests; the
providers are stateless so this is safe."""

from __future__ import annotations

import pytest

from crypto import MLDSAProvider, RSA4096Provider, SLHDSAProvider

MESSAGE = b"SUBSTATION-017: breaker-7 trip signal, seq=42"


@pytest.fixture(scope="session")
def message() -> bytes:
    return MESSAGE


@pytest.fixture(scope="session")
def rsa_provider() -> RSA4096Provider:
    return RSA4096Provider()


@pytest.fixture(scope="session")
def rsa_keypair(rsa_provider):
    return rsa_provider.generate_keypair()


@pytest.fixture(scope="session")
def mldsa_provider() -> MLDSAProvider:
    return MLDSAProvider("mldsa65")


@pytest.fixture(scope="session")
def mldsa_keypair(mldsa_provider):
    return mldsa_provider.generate_keypair()


@pytest.fixture(scope="session")
def slhdsa_provider() -> SLHDSAProvider:
    return SLHDSAProvider("slhdsa-sha2-128s")


@pytest.fixture(scope="session")
def slhdsa_keypair(slhdsa_provider):
    return slhdsa_provider.generate_keypair()
