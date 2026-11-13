# Crypto Capability Interface — Handoff Document for the Migration Platform

**From:** Poojita (Cryptography workstream)
**For:** Pranshita (Migration Platform workstream — inventory, assessment, recommendations, migrations, API, dashboard)
**Status:** Interface v1 — implemented and tested (`crypto_agility/`)
**Basis:** Technical Design Specification §5, §10.5, §21, §22, §26, §27

---

## 1. What you get from this layer

The crypto layer answers exactly three kinds of questions for your platform, deterministically and explainably:

1. **What cryptographic capabilities exist** in this deployment (registry + capability records)?
2. **Which signature modes** (classical / hybrid / PQ) are feasible right now, and what does each require?
3. **How do the algorithms actually perform** (measured keygen/sign/verify times, key and signature sizes)?

Boundary (spec §30, and worth repeating): your rule-based recommendation engine owns asset assessment, scoring, and recommendations. This layer supplies the facts; it never decides that an asset should migrate.

All code below runs against `create_default_registry()`.

## 2. Canonical algorithm identifiers

Use these exact ids in configuration, database rows and API payloads:

| `algorithm_id` | Name | Family | Standard | Parameter set | NIST level | Quantum-vulnerable |
|---|---|---|---|---|---|---|
| `rsa4096` | RSA-4096 | classical | FIPS 186-5 / PKCS#1 v2.2 | RSASSA-PSS, SHA-256, salt=32 | ~152-bit classical | **yes** |
| `mldsa44` | ML-DSA-44 | pq | FIPS 204 | ML-DSA-44 | category 2 | no |
| `mldsa65` | ML-DSA-65 | pq | FIPS 204 | ML-DSA-65 | category 3 | no |
| `mldsa87` | ML-DSA-87 | pq | FIPS 204 | ML-DSA-87 | category 5 | no |
| `slhdsa-sha2-128s` | SLH-DSA-SHA2-128s | pq | FIPS 205 | SLH-DSA-SHA2-128s | category 1 | no |
| `RSA4096-MLDSA` | RSA-4096 + ML-DSA-65 | hybrid | RFC 9794 terminology | composite | max(classical, cat 3) | no (composite) |
| `picnic` | Picnic | pq | research candidate | picnic3l1 | category 1 | no — **candidate only, not implemented** |

The project's primary configuration per the spec: `rsa4096` + `mldsa65` + hybrid `RSA4096-MLDSA`.

## 3. Setup

```python
from crypto_agility.policies import create_default_registry
from crypto_agility.migration_logic import CryptoCapabilityCatalog, TransitionOptions, measure_algorithms

registry = create_default_registry()
catalog = CryptoCapabilityCatalog(registry)
transitions = TransitionOptions(registry)
```

## 4. Querying capabilities (feeds `/api/algorithms`, `/api/pqc/candidates`, DB seed)

```python
catalog.available_algorithms()      # implemented algorithms only
catalog.algorithm_details("mldsa65")
catalog.unavailable_candidates()    # declared but not implemented
catalog.capability_report()         # everything, JSON-serializable
```

Real output of `catalog.algorithm_details("mldsa65")`:

```json
{
  "name": "ML-DSA-65",
  "family": "pq",
  "standard": "FIPS 204 (ML-DSA)",
  "security_level": "NIST category 3",
  "key_size": 1952,
  "signature_size": 3309,
  "implementation": "pqcrypto (Rust bindings)",
  "algorithm_id": "mldsa65",
  "parameter_set": "ML-DSA-65",
  "secret_key_size": 4032,
  "quantum_vulnerable": false,
  "implemented": true,
  "supported_operations": ["keygen", "sign", "verify"],
  "notes": ""
}
```

The first seven fields are exactly the spec §21 `PQCAlgorithm` entity (name, family, standard, security_level, key_size, signature_size, implementation) — you can seed your `pqc algorithm` table directly from `capability_report()["implemented"]`.

**Implemented vs. candidate (normative semantics):**

- `implemented: true` → a working provider is registered; the platform may select and use it.
- `implemented: false` (candidate) → the algorithm is registered for visibility/evaluation but has **no** implementation. It appears in `capability_report()["candidates"]` / `unavailable_candidates()`, `is_available()` returns `False`, and any attempt to *use* it raises `ProviderUnavailableError`.
- Never assume a candidate can be selected "once we add a provider" — when a provider lands, it registers itself and `implemented` flips to `true` everywhere; no platform code changes.

## 5. Availability checks (for the compatibility & recommendation rules)

```python
catalog.is_available("mldsa87")        # -> True
catalog.check_availability("picnic")   # explainable dict:
# {'algorithm_id': 'picnic', 'available': False,
#  'reason': 'registered as evaluated candidate only; no provider implemented'}
catalog.check_availability("falcon512")
# {'algorithm_id': 'falcon512', 'available': False,
#  'reason': "unknown algorithm 'falcon512'; it is not in the registry"}
```

Three distinguishable outcomes: available / registered-but-unimplemented / completely unknown. Recommendation Rule 5/6 (PQ feasibility) should treat "unknown" as a configuration error and "candidate" as not-migrateable-now.

## 6. Transition-mode feasibility (for migration planning)

```python
transitions.supported_modes()          # -> ['classical', 'hybrid', 'pq']
transitions.mode_requirements("hybrid")
transitions.check_mode("hybrid").to_dict()
transitions.check_algorithm_for_mode("pq", "mldsa87").to_dict()
```

Real output of `check_algorithm_for_mode("pq", "rsa4096")`:

```json
{
  "requested_mode": "pq",
  "supported": false,
  "blockers": ["algorithm 'rsa4096' has family 'classical'; mode 'pq' requires family 'pq'"],
  "explanation": "family mismatch between 'rsa4096' and mode 'pq'",
  "requirements": {"required_families": ["pq"], "default_algorithm_ids": ["mldsa65"],
                   "description": "pure post-quantum signatures (post-migration end state)"}
}
```

These answers are pure functions of the registry state — deterministic, rule-based, auditable. They tell the engine *whether the crypto layer could serve a target mode/algorithm*, not *whether an asset should migrate*.

## 7. Selecting providers for actual crypto work

When the platform needs to *do* crypto (e.g. generate the PQ key in migration plan step 04), it must go through explicit configuration — never hard-code an algorithm:

```python
from crypto_agility.policies import CryptoConfiguration, CryptoMode, ProviderSelector

selector = ProviderSelector(registry, CryptoConfiguration(CryptoMode.HYBRID))
selector.signing_algorithm_id()        # 'RSA4096-MLDSA' - record this with artifacts
provider = selector.provider()         # one uniform interface for every mode
kp = provider.generate_keypair()       # hybrid mode -> composite key pair
sig = provider.sign(message, kp.private_key)
provider.verify(message, sig, kp.public_key)   # True

selector.verification_provider_for("RSA4096-MLDSA")  # exact lookup, NO fallback
selector.is_compatible_with("rsa4096")               # False - cannot silently verify with another algorithm
selector.describe().to_dict()                        # explainable selection record for evidence logs
```

Guarantees: bad configurations raise `ConfigurationError` **before** any crypto runs; unknown algorithms raise `UnsupportedAlgorithmError`; candidate-only algorithms cannot be selected; selection is deterministic (`describe()` is stable).

## 8. Measured performance (spec §10.5 / §27 — real numbers, not claims)

```python
from crypto_agility.migration_logic import measure_algorithms

profiles = measure_algorithms(registry, ["rsa4096", "mldsa65", "RSA4096-MLDSA"], iterations=3)
# -> {algorithm_id: {...}} JSON-ready; medians of `iterations` runs, 1 KiB default message
```

Measured on this machine (medians, 1 KiB message — re-run `python examples/demo.py` for current numbers):

| algorithm | keygen ms | sign ms | verify ms | pk B | sig B |
|---|---|---|---|---|---|
| rsa4096 | 201.8 | 876.1 | 0.33 | 550 | 512 |
| mldsa65 | 0.4 | 12.9 | 0.59 | 1952 | 3309 |
| slhdsa-sha2-128s | 62.9 | 390.1 | 0.40 | 32 | 7856 |
| RSA4096-MLDSA | 793.5 | 787.6 | 0.85 | 3361 | 5165 |

Each profile includes `measured_at`, `iterations`, `message_bytes` and `backend`, so your assessment records stay auditable. For RSA-4096 use `iterations=1` for keygen-heavy runs or `include_keygen=False` to time only sign/verify.

## 9. Error responses (what your code should catch)

All from `crypto.errors`, all with key-material-free messages:

| Exception | When | Example trigger |
|---|---|---|
| `UnsupportedAlgorithmError` | id not in registry | `registry.get_provider("falcon512")` |
| `ProviderUnavailableError` | known but candidate-only | `registry.get_provider("picnic")` |
| `ConfigurationError` | bad mode/algorithm in config, duplicate registration | `CryptoConfiguration(CryptoMode.PQ, pq_algorithm="picnic")` |
| `InvalidKeyError` | malformed / wrong-parameter-set key | using an `mldsa44` key with the `mldsa65` provider |
| `MalformedSignatureError` | structurally broken signature data | truncated hybrid signature |

Note the deliberate distinction: a signature that is well-formed but *wrong* is **not** an exception — `verify()` returns `False`. Exceptions mean "the request itself is invalid".

## 10. If you need a new algorithm

Adding an algorithm requires no platform changes:

1. Implement a `CryptoProvider` subclass (see `crypto/pq/mldsa_provider.py` as the template).
2. `registry.register_provider(MyProvider())` — or `register_candidate(...)` if it's evaluation-only.
3. It immediately appears in `available_algorithms()`, mode checks, and the capability report.

Do **not** special-case algorithm ids in platform code; query the catalog instead. If the catalog is missing a field your engine needs, tell me — we extend `ProviderCapabilities` in one place rather than scraping provider internals.

## 11. Where to look in the repo

| What | Where |
|---|---|
| Registry + candidate semantics | `crypto_agility/policies/registry.py` |
| Selection + configuration validation | `crypto_agility/policies/selection.py` |
| Capability catalog (your main API) | `crypto_agility/migration_logic/capabilities.py` |
| Transition-mode logic | `crypto_agility/migration_logic/transition.py` |
| Performance measurement | `crypto_agility/migration_logic/metrics.py` |
| Runnable tests of every claim above | `tests/crypto/test_registry_and_selection.py`, `test_migration_capabilities.py` |
| Live demo with real outputs | `python examples/demo.py` steps [8]–[12] |
