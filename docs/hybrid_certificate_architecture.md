# Hybrid Certificate Architecture — Interface Contract for the PKI Workstream

**From:** Poojita (Cryptography + Architecture workstream)
**For:** Ayanna (PKI / CA implementation workstream)
**Status:** Proposed contract v1 — to be agreed before either side builds tightly coupled code
**Basis:** Technical Design Specification §6, §7, §8; RFC 9794 terminology; this repository's `crypto/` package (Phases 1–2 implemented and tested)

---

## 1. What this document is

This defines **how the cryptographic components I built fit into the certificate system you are implementing**: the hybrid certificate data model, which bytes get signed, how verification is handed off between our layers, and what each layer owns. Everything below is implemented in `crypto/certificates/` and covered by `tests/crypto/test_certificate_model.py`, so you can run the contract, not just read it.

**Scope reminder (spec §30):** I own the hybrid certificate *architecture*; you own the CA, certificate operations, chains, revocation, renewal and rotation. Nothing here implements a CA.

---

## 2. The hybrid certificate data model

Conceptual model (`crypto/certificates/model.py::HybridCertificateModel`), matching spec §7 field-for-field:

| Field | Type | Notes |
|---|---|---|
| `subject` | `str` | Subject identity |
| `issuer` | `str` | Issuer identity |
| `serial_number` | positive `int` | Assigned by your CA |
| `not_before` / `not_after` | tz-aware `datetime` | Validity interval; UTC normalized |
| `classical_public_key` | `PublicKey(algorithm="rsa4096")` | RSA-4096 SPKI DER inside |
| `pq_public_key` | `PublicKey(algorithm="mldsa65")` | Raw FIPS 204 public key inside |
| `extensions` | `Mapping[str, bytes]` | Opaque bag; semantics agreed with you; serialized key-sorted |
| `signature_algorithm` | `str` | `"RSA4096-MLDSA"` (the composite identifier) |
| `signature` | `HybridSignature \| None` | Populated at issuance; `None` until signed |

`HybridSignature` itself is the spec §6 object — `{"algorithm": "RSA4096-MLDSA", "rsa_signature": b64, "mldsa_signature": b64}` as canonical JSON.

**Key material representations the certificate carries:**

| Component | Canonical encoding |
|---|---|
| RSA-4096 public key | DER `SubjectPublicKeyInfo` |
| RSA-4096 private key (CA only) | PKCS#8 DER |
| ML-DSA public key | raw FIPS 204 bytes (1952 for ML-DSA-65) |
| ML-DSA private key (CA only) | raw FIPS 204 bytes |

## 3. Which component signs what

**Both components sign the identical to-be-signed (TBS) bytes.** `HybridCertificateModel.to_be_signed_bytes()` produces a deterministic canonical JSON over every field *except* `signature` (sorted keys, compact separators, UTC ISO-8601 timestamps, base64 key/extension values, plus a `profile` tag). Properties:

- Any change to any field (subject, serial, keys, extensions, validity) changes the TBS bytes → signature verification fails. This is how the verifier binds the signature to the certificate content.
- There is no separate "RSA part" and "ML-DSA part" of the certificate; the composite signature covers one well-defined byte string.

At issuance your CA code calls the crypto layer with the unsigned model + the CA's two private keys; both component signatures are computed over the TBS bytes and packaged into the hybrid signature. The reference implementation is `crypto/certificates/contracts.py::CertificateSigningService`.

## 4. Issuance flow (crypto side)

```python
from crypto import RSA4096Provider, MLDSAProvider
from crypto.certificates import CertificateSigningService, HybridCertificateModel
from crypto.hybrid import HybridSigner

signing = CertificateSigningService(HybridSigner(RSA4096Provider(), MLDSAProvider("mldsa65")))

signed = signing.sign_certificate(
    unsigned_certificate,          # HybridCertificateModel (signature=None)
    ca_rsa4096_private_key,        # PrivateKey("rsa4096", ...)  - your CA key
    ca_mldsa_private_key,          # PrivateKey("mldsa65", ...)  - your CA key
)
assert signed.is_signed()
```

Guarantees: refuses to double-sign; refuses if the declared `signature_algorithm` doesn't match the signer; if either component signing fails, **no** signature object is returned (no partial results).

## 5. Verification flow (crypto side → PKI handoff)

The division of labor from spec §8, made explicit:

1. **You** validate everything that is not a signature: validity window, issuer/chain policy, revocation, renewal status.
2. When you need the signature checked, hand over the certificate **plus the issuer's two component public keys** (from the issuer certificate or trust anchor — you own that lookup).
3. **I** verify both components over the TBS bytes under the strict two-component policy and return a structured result.
4. Your chain/validity/revocation logic combines my result with your own checks. Signature verification **never replaces** those checks.

```python
from crypto.certificates import CertificateVerificationService, CertificateValidationRequest
from crypto.hybrid import HybridVerifier

verifying = CertificateVerificationService(HybridVerifier(RSA4096Provider(), MLDSAProvider("mldsa65")))

result = verifying.verify_certificate_signature(
    certificate, issuer_rsa4096_public_key, issuer_mldsa_public_key
)
result.accepted          # bool - both components verified
result.components        # per-component diagnostics: VERIFIED / INVALID / MISSING / MALFORMED / ...
result.reason            # human-readable, key-material-free

# or the explicit handoff object:
outcome = verifying.verify_request(CertificateValidationRequest(
    certificate, issuer_rsa4096_public_key, issuer_mldsa_public_key))
outcome.signature_accepted   # bool for your ACCEPT/REJECT decision input
```

Component-level diagnostics are always available (`result.to_dict()`), so your validation layer can log *why* a signature failed without ever seeing key material.

**Public-key extraction** (for chain building, and later for verifying an asset's own signatures under its certificate):

```python
keys = verifying.extract_public_keys(certificate)   # {"classical": PublicKey, "pq": PublicKey}
```

## 6. Hybrid acceptance policy (normative)

`STRICT_TWO_COMPONENT`: the certificate signature is accepted **only if both** the RSA-4096 and the ML-DSA component verify. One valid component is never sufficient. The policy lives in one place (`crypto/hybrid/verifier.py::HybridAcceptancePolicy`); if we ever add a policy, it is added there and to the tests — nowhere else.

## 7. Responsibility split (agreed boundary)

| Cryptography layer (mine — done) | PKI layer (yours) |
|---|---|
| Key generation (all algorithms) | Root CA / Intermediate CA hierarchy |
| Component + hybrid signing | CA key management, trust anchors |
| Signature verification + policy | Certificate issuance, parsing, lifecycle |
| Serialization formats (TBS, keys, hybrid sigs) | Chain construction & validation |
| Algorithm identifiers & registry | Revocation, renewal, rotation |
| `crypto/certificates` reference services | Accept/Reject decision combining all checks |

## 8. Compatibility boundary (important)

- **This model is not an X.509 certificate and not an interoperable wire format.** It is the conceptual architecture the spec asks for (§7: "We should not claim that our certificate structure itself is a new X.509 standard").
- The `to_dict()` JSON is an internal/demo serialization only.
- Before your implementation starts, we need to agree the applicable certificate **profile and encoding**. RFC 9794 lists the options for PQ/T certificates (composite vs. parallel PKI, hybrid chains, etc.). My crypto layer deliberately supports any of them — the provider interface and the TBS/verification flow don't change — but the encoding decision determines what your `pki/` code produces and parses.
- Until that agreement: don't wire my `HybridCertificateModel.to_dict()` output into your CA file formats, and I won't claim X.509 interop that hasn't been demonstrated.

## 9. Open decisions for our agreement meeting

1. Certificate profile: composite X.509-style encoding vs. two parallel certs vs. other — pick one for the prototype and record it here.
2. Extensions vocabulary: I treat extensions as opaque bytes; you define the names/semantics you need (e.g. `migrationStatus` as in the demo).
3. ML-DSA parameter set for the PKI: I default to **ML-DSA-65** (NIST category 3). If you want 44 or 87 for the prototype, say so — it's a one-line configuration change everywhere.
4. Where CA private keys live in your prototype (my `DevKeyStore` is dev/test only, per the security controls in spec §25).
5. Error surface: PKI code should catch `crypto.errors.*` types only; if you need richer error taxonomy, we extend `crypto/errors.py` together.

## 10. Where to look in the repo

| What | Where |
|---|---|
| Data model + TBS definition | `crypto/certificates/model.py` |
| Signing/verification services + protocols | `crypto/certificates/contracts.py` |
| Hybrid signature object/wire format | `crypto/hybrid/signature.py` |
| Acceptance policy | `crypto/hybrid/verifier.py` |
| Contract tests (runnable spec) | `tests/crypto/test_certificate_model.py` |
| End-to-end demo (issuance + verification) | `examples/demo.py` steps [6]–[7] |
