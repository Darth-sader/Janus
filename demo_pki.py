"""Walk through the PKI module end to end, following SUBSTATION-017's migration.

Run:  python demo_pki.py          (RSA-4096, takes a few seconds)
      python demo_pki.py --fast   (RSA-2048, for a quick run)

Builds a hybrid (RSA + ML-DSA) PKI, issues a classical certificate to a legacy
asset, migrates it to hybrid, shows attacks being rejected, and writes the
certificates to demo_output/ so you can open them.
"""
import json
import sys
import time
from datetime import timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from pki import hybrid
from pki.ca import CertificateAuthority, create_intermediate_ca, create_root_ca
from pki.config import PKIConfig
from pki.issuance import issue_certificate
from pki.keystore import save_private_key
from pki.lifecycle import CertificateManager
from pki.models import CertMode
from pki.parsing import parse_certificate, to_pem
from pki.trust import TrustStore
from pki.validation import ValidationPolicy, validate_certificate

OUT = Path("demo_output")
REQUIRE_PQ = ValidationPolicy(require_pq=True)


def show(label, result) -> None:
    if result.valid:
        print(f"   [OK]   {label}: valid ({result.mode.value})")
    else:
        first = result.issues[0]
        print(f"   [FAIL] {label}: {result.reason.value} - {first.message}")


def main() -> None:
    OUT.mkdir(exist_ok=True)
    key_size = 2048 if "--fast" in sys.argv else 4096
    config = PKIConfig(mode=CertMode.HYBRID, rsa_key_size=key_size)

    print(f"1. Building a hybrid PKI (RSA-{key_size} + {config.pq_algorithm})...")
    root = create_root_ca("Grid Root CA", config)
    inter = create_intermediate_ca(root, "Grid Intermediate CA")
    trust = TrustStore([root.certificate])
    manager = CertificateManager()

    def validate(cert, **kwargs):
        return validate_certificate(cert, trust, [inter.certificate], crls=manager.current_crls(), **kwargs)

    print("\n2. SUBSTATION-017 starts with a classical certificate (legacy asset)")
    asset = manager.issue(inter, "substation-017.grid.test", mode=CertMode.CLASSICAL)
    classical_cert = asset.certificate
    show("normal policy", validate(classical_cert))
    show("PQ-required policy", validate(classical_cert, policy=REQUIRE_PQ))

    print("\n3. The migration advisor recommends HYBRID MIGRATION, so we migrate it")
    manager.migrate(asset.cert_id, CertMode.HYBRID)
    show("new hybrid certificate, PQ-required policy", validate(asset.certificate, policy=REQUIRE_PQ))
    show("old classical certificate", validate(classical_cert))

    print("\n4. Attacks and failures are rejected with a specific reason")
    der = asset.certificate.public_bytes(serialization.Encoding.DER)
    tampered = x509.load_der_x509_certificate(der.replace(b"substation-017", b"substation-666", 1))
    show("domain name changed after signing", validate(tampered))
    attacker = CertificateAuthority(
        inter.certificate,
        hybrid.HybridPrivateKey(inter.private_key.classical, hybrid.generate_ml_dsa_key(config.pq_algorithm)),
        inter.signer, config)
    forged = issue_certificate(attacker, "substation-017.grid.test")
    show("RSA forged, ML-DSA not (quantum attacker)", validate(forged.certificate))
    later = asset.certificate.not_valid_after_utc + timedelta(days=1)
    show("checked after expiry", validate(asset.certificate, at_time=later))
    show("root not in the trust store",
         validate_certificate(asset.certificate, TrustStore(), [inter.certificate, root.certificate]))

    print("\n5. Lifecycle: renew, then revoke")
    manager.renew(asset.cert_id)
    show("after renewal", validate(asset.certificate))
    manager.revoke(asset.cert_id, x509.ReasonFlags.key_compromise)
    show("after revocation", validate(asset.certificate))

    print("\n6. Cost of going hybrid")
    size = lambda c: len(c.public_bytes(serialization.Encoding.DER))
    start = time.perf_counter()
    validate(asset.certificate)
    elapsed = (time.perf_counter() - start) * 1000
    print(f"   classical certificate:       {size(classical_cert):>6} bytes")
    print(f"   hybrid certificate:          {size(asset.certificate):>6} bytes")
    print(f"   one hybrid chain validation: {elapsed:>6.1f} ms")

    print("\n7. Status record for the migration platform (Person 3)")
    status = asset.to_dict()
    print(json.dumps({k: status[k] for k in ("cert_id", "common_name", "state", "mode",
                                              "public_key_algorithm", "previous_serials")}, indent=2))
    for h in asset.history:
        print(f"   {(h.from_state.value if h.from_state else '-'):>8} -> {h.to_state.value:<8} {h.note}")

    for name, cert in [("root", root.certificate), ("intermediate", inter.certificate),
                       ("classical-leaf", classical_cert), ("hybrid-leaf", asset.certificate)]:
        (OUT / f"{name}.crt").write_bytes(to_pem(cert))
    save_private_key(asset.private_key, OUT / "hybrid-leaf.key.pem", b"demo-passphrase")
    print(f"\nCertificates written to {OUT.resolve()}")
    print("Double-click a .crt file there to view it in Windows' certificate viewer.")
    print(f"Leaf record: {parse_certificate(asset.certificate).signature_algorithm}")


if __name__ == "__main__":
    main()
