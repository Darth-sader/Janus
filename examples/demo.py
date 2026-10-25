"""End-to-end demonstration of the cryptography layer (Phases 1-4).

Run from the project root:

    python examples/demo.py

Shows the full story: register algorithms -> generate component keys ->
hybrid sign -> verify -> tamper rejection -> serialized round trip ->
certificate issuance/verification -> registry query -> capability
report -> transition checks -> measured performance.
"""

from __future__ import annotations

import sys
from pathlib import Path

# allow `python examples/demo.py` from the project root or anywhere
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from datetime import datetime, timedelta, timezone

from crypto import MLDSAProvider, RSA4096Provider
from crypto.certificates import (
    CertificateSigningService,
    CertificateVerificationService,
    HybridCertificateModel,
)
from crypto.hybrid import HybridSigner, HybridVerifier
from crypto_agility.migration_logic import CryptoCapabilityCatalog, TransitionOptions, measure_algorithms
from crypto_agility.policies import CryptoConfiguration, CryptoMode, ProviderSelector, create_default_registry

LINE = "=" * 74


def main() -> None:
    print(LINE)
    print("HYBRID PQC PKI - CRYPTOGRAPHY LAYER DEMONSTRATION")
    print(LINE)

    # ---- phase 1/2: component + hybrid cryptography ----------------------
    rsa, mldsa = RSA4096Provider(), MLDSAProvider("mldsa65")
    message = b"SUBSTATION-017 telemetry authentication token"
    rsa_kp, mldsa_kp = rsa.generate_keypair(), mldsa.generate_keypair()
    print(f"\n[1] component key pairs generated: {rsa.display_name}, {mldsa.display_name}")

    signer = HybridSigner(rsa, mldsa)
    verifier = HybridVerifier(rsa, mldsa)
    hybrid_sig = signer.sign(message, rsa_kp.private_key, mldsa_kp.private_key)
    print(f"[2] hybrid signature ({hybrid_sig.algorithm}): "
          f"rsa={len(hybrid_sig.rsa_signature)}B + mldsa={len(hybrid_sig.mldsa_signature)}B "
          f"-> {len(hybrid_sig.to_json_bytes())}B serialized")

    result = verifier.verify(message, hybrid_sig, rsa_kp.public_key, mldsa_kp.public_key)
    print(f"[3] verification of valid message: accepted={result.accepted}")
    print(f"    {result.reason}")

    result = verifier.verify(b"tampered " + message, hybrid_sig, rsa_kp.public_key, mldsa_kp.public_key)
    print(f"[4] verification of tampered message: accepted={result.accepted}")
    for component in result.components:
        print(f"    {component.component}: {component.status.value}")

    wire = hybrid_sig.to_json_bytes()
    restored = verifier.verify(message, wire, rsa_kp.public_key, mldsa_kp.public_key)
    print(f"[5] serialized round trip (canonical JSON): accepted={restored.accepted}")

    # ---- phase 3: hybrid certificate (conceptual model + contract) -------
    print(LINE)
    print("HYBRID CERTIFICATE (conceptual model - NOT an X.509 encoding)")
    now = datetime.now(timezone.utc)
    cert = HybridCertificateModel(
        subject="CN=SUBSTATION-017",
        issuer="CN=Grid-Intermediate-CA",
        serial_number=17,
        not_before=now,
        not_after=now + timedelta(days=365),
        classical_public_key=rsa_kp.public_key,
        pq_public_key=mldsa_kp.public_key,
        extensions={"migrationStatus": b"HYBRID"},
    )
    ca_rsa_kp, ca_mldsa_kp = rsa.generate_keypair(), mldsa.generate_keypair()
    signing = CertificateSigningService(HybridSigner(rsa, mldsa))
    verifying = CertificateVerificationService(HybridVerifier(rsa, mldsa))
    signed = signing.sign_certificate(cert, ca_rsa_kp.private_key, ca_mldsa_kp.private_key)
    print(f"\n[6] issued hybrid certificate serial={signed.serial_number} "
          f"(TBS={len(signed.to_be_signed_bytes())}B, both CA components sign the same TBS bytes)")

    check = verifying.verify_certificate_signature(signed, ca_rsa_kp.public_key, ca_mldsa_kp.public_key)
    print(f"[7] certificate signature verification: accepted={check.accepted}")

    # ---- phase 4: crypto-agility and migration logic ----------------------
    print(LINE)
    print("CRYPTO-AGILITY: REGISTRY, SELECTION, CAPABILITIES, TRANSITION")
    registry = create_default_registry()
    print("\n[8] registered algorithms:")
    for entry in registry.list_algorithms():
        state = "implemented" if entry.implemented else "candidate only"
        print(f"    {entry.algorithm_id:<20} {entry.family:<9} {state}")

    for mode in CryptoMode:
        selector = ProviderSelector(registry, CryptoConfiguration(mode))
        decision = selector.describe()
        print(f"[9] mode {mode.value:<9} -> {decision.algorithm_id} ({decision.provider_display_name})")

    catalog = CryptoCapabilityCatalog(registry)
    print(f"\n[10] availability examples:")
    for algorithm_id in ("mldsa65", "picnic", "falcon512"):
        print(f"     {catalog.check_availability(algorithm_id)}")

    transitions = TransitionOptions(registry)
    print(f"\n[11] transition modes supported: {transitions.supported_modes()}")

    print("\n[12] measured crypto performance (medians, 1 KiB message):")
    profiles = measure_algorithms(registry, ["rsa4096", "mldsa65", "slhdsa-sha2-128s", "RSA4096-MLDSA"], iterations=3)
    header = f"    {'algorithm':<16}{'keygen ms':>11}{'sign ms':>10}{'verify ms':>11}{'pk B':>7}{'sig B':>8}"
    print(header)
    for algorithm_id, p in profiles.items():
        keygen = f"{p['keygen_ms']:.1f}" if p["keygen_ms"] >= 0 else "n/a"
        print(f"    {algorithm_id:<16}{keygen:>11}{p['sign_ms']:>10.2f}{p['verify_ms']:>11.2f}"
              f"{p['public_key_bytes']:>7}{p['signature_bytes']:>8}")

    print(LINE)
    print("all demonstrated operations ran through the same CryptoProvider interface")


if __name__ == "__main__":
    main()
