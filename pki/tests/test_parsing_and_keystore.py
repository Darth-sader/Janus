import json

import pytest
from cryptography.hazmat.primitives import serialization

from pki.keystore import load_private_key, save_private_key
from pki.models import CertMode, CertRole, LifecycleState
from pki.parsing import load_certificate, parse_certificate, to_pem


def test_parse_leaf(leaf):
    rec = parse_certificate(leaf.certificate)
    assert rec.role is CertRole.LEAF
    assert rec.is_ca is False
    assert "CN=app.example.test" in rec.subject
    assert "CN=Test Intermediate CA" in rec.issuer
    assert rec.public_key_algorithm == "RSA-2048"
    assert rec.signature_algorithm == "sha256WithRSAEncryption"
    assert rec.mode is CertMode.CLASSICAL
    assert rec.state is LifecycleState.ACTIVE
    assert rec.san_dns_names == ["app.example.test", "www.example.test"]


def test_parse_roles(root_ca, intermediate_ca):
    assert parse_certificate(root_ca.certificate).role is CertRole.ROOT_CA
    assert parse_certificate(intermediate_ca.certificate).role is CertRole.INTERMEDIATE_CA


def test_pem_and_der_round_trip(leaf):
    pem = to_pem(leaf.certificate)
    der = leaf.certificate.public_bytes(serialization.Encoding.DER)
    assert load_certificate(pem) == leaf.certificate
    assert load_certificate(pem.decode()) == leaf.certificate
    assert load_certificate(der) == leaf.certificate


def test_record_is_json_serialisable(leaf):
    data = json.loads(json.dumps(parse_certificate(leaf.certificate).to_dict()))
    assert data["role"] == "leaf"
    assert data["state"] == "ACTIVE"
    assert len(data["fingerprint_sha256"]) == 64


def test_keystore_round_trip(tmp_path, leaf):
    path = tmp_path / "leaf.key.pem"
    save_private_key(leaf.private_key, path, b"correct horse")
    assert b"ENCRYPTED PRIVATE KEY" in path.read_bytes()
    loaded = load_private_key(path, b"correct horse")
    assert loaded.private_numbers() == leaf.private_key.private_numbers()


def test_keystore_wrong_passphrase(tmp_path, leaf):
    path = tmp_path / "leaf.key.pem"
    save_private_key(leaf.private_key, path, b"correct horse")
    with pytest.raises(ValueError):
        load_private_key(path, b"wrong")
