# `pki/`: PKI & Certificate Module (Person 2)

Root and Intermediate CAs, certificate issuance, parsing, chain validation,
trust management, CRL revocation, renewal/rotation and classical → hybrid → PQ
migration. Supports three certificate modes:

| Mode | Keys and signatures |
|---|---|
| `classical` | RSA (4096 by default) |
| `hybrid` | RSA + ML-DSA; **both** signatures must verify |
| `pq` | ML-DSA only |

## Files

| File | Responsibility |
|---|---|
| `models.py` | Enums and data records (`CertificateRecord`, `ValidationResult`, …) |
| `config.py` | `PKIConfig`: mode, key sizes, validity periods |
| `provider.py` | One signer per mode; the only place that calls RSA / ML-DSA |
| `hybrid.py` | How the ML-DSA key and signature are stored in a certificate |
| `ca.py`, `issuance.py` | Create CAs and issue server certificates |
| `parsing.py` | Load PEM/DER and turn a certificate into a JSON-friendly record |
| `signatures.py`, `trust.py` | Verify signatures; the set of trusted roots |
| `validation.py` | Chain validation with a detailed result |
| `revocation.py` | Per-CA revocation registry that publishes signed CRLs |
| `lifecycle.py` | `CertificateManager`: issue, renew, rotate, migrate, revoke |
| `keystore.py` | Passphrase-encrypted key files |

## Quick start

```python
from pki.config import PKIConfig
from pki.models import CertMode
from pki.ca import create_root_ca, create_intermediate_ca
from pki.lifecycle import CertificateManager
from pki.trust import TrustStore
from pki.validation import validate_certificate

config = PKIConfig(mode=CertMode.HYBRID)
root = create_root_ca("Grid Root CA", config)
inter = create_intermediate_ca(root, "Grid Intermediate CA")

manager = CertificateManager()
asset = manager.issue(inter, "substation-017.grid.test", mode=CertMode.CLASSICAL)
manager.migrate(asset.cert_id, CertMode.HYBRID)

result = validate_certificate(asset.certificate, TrustStore([root.certificate]),
                              [inter.certificate], crls=manager.current_crls())
print(result.to_dict())   # {"valid": true, "reason": "OK", "issues": [], ...}
print(asset.to_dict())    # status record for the migration platform
```

Run the walkthrough with `python demo_pki.py` and the tests with `python -m pytest pki`.

## For Person 3 (migration platform)

- `ManagedCertificate.to_dict()` gives one status record per asset credential:
  `cert_id`, `state` (GENERATE / ISSUE / ACTIVE / RENEW / REVOKE / REVOKED),
  `mode`, `expired`, `previous_serials`, `history`, plus the certificate fields.
- `ValidationResult.to_dict()` gives `valid`, `reason` and every issue found, with
  reasons: `EXPIRED`, `NOT_YET_VALID`, `BAD_SIGNATURE`, `BAD_PQ_SIGNATURE`,
  `BAD_CHAIN`, `UNTRUSTED_ROOT`, `REVOKED`, `REVOCATION_UNKNOWN`, `POLICY_VIOLATION`.

## Defaults to confirm with the team

| Open question | Default used | Where to change it |
|---|---|---|
| 1. Hybrid certificate encoding | RSA certificate plus three non-critical extensions modelled on X.509's alternative-signature extensions (see `hybrid.py`) | `hybrid.py`, `provider.HybridSigner` |
| 2. CryptoProvider interface | Signers call the `cryptography` library directly | `provider.py` |
| 3. Hybrid verification | Both signatures must verify, no fallback | `signatures.verify_signatures` |
| 4. PQ library | `cryptography` ≥ 50 (native ML-DSA); parameter set ML-DSA-65 | `config.pq_algorithm` |
| 5. Revocation | CRLs only (no OCSP), valid for 7 days | `revocation.py` |
| 6. Integration with the platform | Python API + JSON records; no REST endpoints yet | `lifecycle.py` |
| 7. Key storage | PKCS#8 PEM files encrypted with a passphrase | `keystore.py` |

## Known limitations (prototype)

- The hybrid encoding is our own, modelled on X.509 alternative signatures. It is
  not claimed to be a standard and has not been tested with other software.
- A hybrid CA's CRL is signed with RSA only.
- No OCSP, no HSM, no CA key rotation (leaf rotation only), no persistence:
  `CertificateManager` keeps everything in memory.
