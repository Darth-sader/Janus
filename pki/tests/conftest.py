import pytest

from pki.ca import create_intermediate_ca, create_root_ca
from pki.config import PKIConfig
from pki.issuance import issue_certificate
from pki.models import CertMode
from pki.trust import TrustStore

# 2048-bit keys keep the test suite fast; production default is 4096.
TEST_CONFIG = PKIConfig(rsa_key_size=2048)
HYBRID_CONFIG = PKIConfig(mode=CertMode.HYBRID, rsa_key_size=2048)
PQ_CONFIG = PKIConfig(mode=CertMode.PQ)


@pytest.fixture(scope="session")
def config():
    return TEST_CONFIG


# ---------- classical hierarchy ----------

@pytest.fixture(scope="session")
def root_ca(config):
    return create_root_ca("Test Root CA", config)


@pytest.fixture(scope="session")
def intermediate_ca(root_ca):
    return create_intermediate_ca(root_ca, "Test Intermediate CA")


@pytest.fixture(scope="session")
def leaf(intermediate_ca):
    return issue_certificate(intermediate_ca, "app.example.test",
                             dns_names=["app.example.test", "www.example.test"])


@pytest.fixture
def trust_store(root_ca):
    return TrustStore([root_ca.certificate])


# ---------- hybrid and PQ hierarchies ----------

@pytest.fixture(scope="session")
def hybrid_root():
    return create_root_ca("Hybrid Root CA", HYBRID_CONFIG)


@pytest.fixture(scope="session")
def hybrid_intermediate(hybrid_root):
    return create_intermediate_ca(hybrid_root, "Hybrid Intermediate CA")


@pytest.fixture(scope="session")
def hybrid_leaf(hybrid_intermediate):
    return issue_certificate(hybrid_intermediate, "substation-017.example.test")


@pytest.fixture(scope="session")
def pq_root():
    return create_root_ca("PQ Root CA", PQ_CONFIG)


@pytest.fixture
def hybrid_trust_store(hybrid_root):
    return TrustStore([hybrid_root.certificate])
