# Hybrid Post-Quantum PKI — Cryptography Layer (Poojita's workstream)

Crypto-agile cryptography layer for the Hybrid PQ/T PKI & Cryptographic Migration Assistance Framework:
a common `CryptoProvider` interface, RSA-4096 + ML-DSA (FIPS 204) providers, SLH-DSA (FIPS 205) as an
additional PQ family, the parallel/composite **RSA4096-MLDSA** hybrid construction, the conceptual
**hybrid certificate** architecture, and the **crypto-agility / migration-logic** surface consumed by
the migration platform.

Primary configuration (per the Technical Design Specification):
**classical = RSA-4096** · **PQ = ML-DSA-65** · **hybrid = RSA-4096 + ML-DSA** · SLH-DSA as candidate family.

All primitives come from maintained libraries — `cryptography` (OpenSSL) for RSA-PSS and `pqcrypto`
(FIPS 204/205 conformant Rust bindings) for ML-DSA/SLH-DSA. Nothing is hand-implemented.

## Module layout

```
crypto/                          cryptography layer (Phases 1-3)
├── errors.py                    exception hierarchy (key-material-free messages)
├── keys/                        algorithm-tagged key types + dev/test key store
├── rsa/                         RSA-4096 provider (RSASSA-PSS, SHA-256, salt=32)
├── pq/                          ML-DSA (FIPS 204) + SLH-DSA (FIPS 205) providers
├── hybrid/                      HybridSignature, HybridSigner, HybridVerifier, generic adapter
├── verification/                shared result types (overall + per-component diagnostics)
└── certificates/                conceptual hybrid certificate model + PKI interface contracts

crypto_agility/                  crypto-agility layer (Phase 4)
├── interfaces/                  the CryptoProvider contract + capability records
├── policies/                    algorithm registry + provider selection (no silent fallback)
└── migration_logic/             capability catalog, transition modes, performance metrics

tests/crypto/                    independently runnable test suite (no teammates' modules needed)
docs/                            interface contracts for the other workstreams
examples/demo.py                 end-to-end demonstration with measured numbers
```

## Quickstart

```bash
# Python 3.10+; from the project root
pip install -e .[dev]           # or: pip install cryptography pqcrypto pytest

python -m pytest tests/ -q      # run the full test suite
python examples/demo.py         # end-to-end demo: sign -> verify -> tamper -> certify -> benchmark
```

## The CryptoProvider interface

Every algorithm is reachable through the same contract (`crypto_agility/interfaces/provider.py`):

```python
from crypto import RSA4096Provider, MLDSAProvider

provider = MLDSAProvider("mldsa65")           # or RSA4096Provider()
kp = provider.generate_keypair()
sig = provider.sign(message, kp.private_key)
provider.verify(message, sig, kp.public_key)  # True / False (never raises on bad signature)
provider.serialize_public_key(kp.public_key)  # deterministic wire bytes
...  # deserialize_public_key / serialize_signature / deserialize_signature
```

Contract rules: `verify()` is a predicate (malformed **inputs** raise `crypto.errors.*`, a wrong
signature returns `False`); providers validate key type, size and parameter set; errors never contain
key material; `PrivateKey.__repr__` is redacted.

## Hybrid signatures (RSA4096-MLDSA)

Parallel/composite construction per RFC 9794 terminology — both components sign the **same** message
bytes (no novel combiner), serialized as canonical JSON matching the specification:

```json
{"algorithm": "RSA4096-MLDSA", "rsa_signature": "<b64>", "mldsa_signature": "<b64>"}
```

```python
from crypto.hybrid import HybridSigner, HybridVerifier, HybridAcceptancePolicy

sig = HybridSigner(rsa_provider, mldsa_provider).sign(message, rsa_sk, mldsa_sk)
result = HybridVerifier(rsa_provider, mldsa_provider).verify(message, sig, rsa_pk, mldsa_pk)
result.accepted        # True only under the STRICT_TWO_COMPONENT policy
result.components      # per-component diagnostics (VERIFIED / INVALID / MISSING / ...)
```

Acceptance policy is explicit and strict: **both** components must verify; a single valid component is
never accepted; missing/malformed/mismatched components are reported individually.

## Hybrid certificates (architecture — Ayanna implements the PKI)

`crypto/certificates/` defines the conceptual model (subject, both public keys, issuer, serial,
validity, extensions, hybrid signature info), the exact deterministic to-be-signed bytes that **both**
CA signature components cover, and the signing/verification services the PKI layer calls. It is
deliberately **not** an X.509 encoding — the profile/encoding decision is an open item documented in
**[docs/hybrid_certificate_architecture.md](docs/hybrid_certificate_architecture.md)**.

## Crypto-agility & migration logic (Pranshita consumes this)

```python
from crypto_agility.policies import create_default_registry, CryptoConfiguration, CryptoMode, ProviderSelector
from crypto_agility.migration_logic import CryptoCapabilityCatalog, TransitionOptions, measure_algorithms

registry = create_default_registry()          # rsa4096, mldsa44/65/87, slhdsa-sha2-128s, RSA4096-MLDSA, picnic*
selector = ProviderSelector(registry, CryptoConfiguration(CryptoMode.HYBRID))
selector.provider()                           # one uniform interface for classical / pq / hybrid modes
CryptoCapabilityCatalog(registry).capability_report()   # PQCAlgorithm-aligned records for the platform
measure_algorithms(registry, ["mldsa65"])     # measured keygen/sign/verify + sizes
```

Exact lookups, explainable errors, no silent algorithm fallback; declared-but-unimplemented candidates
(like `picnic`) are visible to the platform but never selectable. The full handoff API with sample
calls and outputs: **[docs/crypto_capabilities_interface.md](docs/crypto_capabilities_interface.md)**.

## Canonical algorithm identifiers

| id | algorithm | standard | quantum-vulnerable |
|---|---|---|---|
| `rsa4096` | RSA-4096 (RSASSA-PSS, SHA-256) | FIPS 186-5 / PKCS#1 v2.2 | yes |
| `mldsa44` / `mldsa65` / `mldsa87` | ML-DSA | FIPS 204 | no |
| `slhdsa-sha2-128s` (+10 more sets) | SLH-DSA | FIPS 205 | no |
| `RSA4096-MLDSA` | hybrid composite | RFC 9794 terminology | no (composite) |

## Design decisions worth knowing

- **RSA-PSS parameters are explicit**: SHA-256, MGF1-SHA-256, salt = 32 bytes (digest length), e = 65537, key size pinned to 4096 bits.
- **ML-DSA parameter sets are part of the algorithm id** (`mldsa65`), so a key from one parameter set can never be used with another — enforced on every operation.
- **Serialization is deterministic** everywhere (canonical JSON, sorted keys, fixed field order); round trips are tested.
- **Key storage** (`crypto/keys/storage.py`) is for development/test keys only: documented JSON envelope, optional passphrase encryption (PBKDF2-HMAC-SHA256 + Fernet). Production CA key management belongs to the PKI workstream.
- **Error hygiene**: third-party exceptions are normalized to `crypto.errors.*`; messages carry identifiers and lengths, never key bytes; `verify()` failing is `False`, not an exception.

## Ownership boundaries (spec §30)

| Workstream | Owns |
|---|---|
| **Poojita (this repo section)** | `crypto/`, `crypto_agility/`, hybrid design, high-level certificate architecture; integration + final validation after handoff |
| **Ayanna** | `pki/` — Root/Intermediate CA, issuance, chains, revocation, renewal, rotation |
| **Pranshita** | `platform/` — inventory, assessment, recommendations, migrations, checklist, DB, API, dashboard |

Deliberately **out of scope** here: CA implementation, asset assessment, recommendation engine, and
any new cryptographic primitive. Phases 5–6 (connecting modules end-to-end, system-wide validation)
start once the teammates' modules land.
