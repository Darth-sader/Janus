from datetime import datetime, timezone

from sqlalchemy.orm import Session

from migration_platform.integrations.crypto_adapter import CryptoAdapter
from migration_platform.models import PQCAlgorithm


def sync_algorithms(
    db: Session,
    crypto_adapter: CryptoAdapter,
) -> dict:
    """
    Synchronize algorithm capabilities from Person 1's
    crypto catalog into Person 3's database.

    Person 1 remains the source of truth.
    """

    algorithms = crypto_adapter.get_normalized_algorithms()

    added = 0
    updated = 0

    for algorithm in algorithms:
        existing = db.query(PQCAlgorithm).filter(
            PQCAlgorithm.algorithm_id == algorithm.algorithm_id
        ).first()

        if existing:
            record = existing
            updated += 1
        else:
            record = PQCAlgorithm(
                algorithm_id=algorithm.algorithm_id
            )
            db.add(record)
            added += 1

        record.name = algorithm.name
        record.family = algorithm.family
        record.standard = algorithm.standard
        record.security_level = str(algorithm.security_level)
        record.key_size = algorithm.key_size
        record.signature_size = algorithm.signature_size
        record.implementation = algorithm.implementation
        record.quantum_vulnerable = algorithm.quantum_vulnerable
        record.implemented = algorithm.implemented
        record.notes = algorithm.notes
        record.last_synced_at = datetime.now(timezone.utc)

    db.commit()

    return {
        "message": "Algorithm synchronization completed",
        "total_received": len(algorithms),
        "added": added,
        "updated": updated,
        "synchronized_at": datetime.now(timezone.utc).isoformat(),
    }