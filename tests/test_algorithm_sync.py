from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from migration_platform.database import Base
from migration_platform.integrations.algorithm_sync import sync_algorithms
from migration_platform.integrations.contracts import AlgorithmCapability
from migration_platform.models import PQCAlgorithm


class MockCryptoAdapter:

    def get_normalized_algorithms(self):
        return [
            AlgorithmCapability(
                algorithm_id="rsa4096",
                name="RSA-4096",
                family="classical",
                standard="RSA",
                security_level="classical",
                key_size=4096,
                implementation="mock-provider",
                quantum_vulnerable=True,
                implemented=True,
                supported_operations=["sign", "verify"],
                notes="Mock RSA algorithm",
            ),
            AlgorithmCapability(
                algorithm_id="mldsa65",
                name="ML-DSA-65",
                family="pq",
                standard="FIPS 204",
                security_level="3",
                implementation="mock-provider",
                quantum_vulnerable=False,
                implemented=True,
                supported_operations=["sign", "verify"],
                notes="Mock PQ algorithm",
            ),
        ]


def create_test_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(bind=engine)

    TestSession = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )

    return engine, TestSession()


def test_sync_adds_algorithms():
    engine, db = create_test_session()

    try:
        result = sync_algorithms(db, MockCryptoAdapter())

        assert result["added"] == 2
        assert result["updated"] == 0

        algorithms = db.query(PQCAlgorithm).all()

        assert len(algorithms) == 2

    finally:
        db.close()
        engine.dispose()


def test_sync_updates_existing_algorithm():
    engine, db = create_test_session()

    try:
        db.add(
            PQCAlgorithm(
                algorithm_id="rsa4096",
                name="Old RSA Name",
                family="classical",
                standard="RSA",
                security_level="classical",
                implemented=True,
            )
        )
        db.commit()

        result = sync_algorithms(db, MockCryptoAdapter())

        assert result["updated"] == 1
        assert result["added"] == 1

        algorithm = db.query(PQCAlgorithm).filter_by(
            algorithm_id="rsa4096"
        ).first()

        assert algorithm.name == "RSA-4096"

    finally:
        db.close()
        engine.dispose()


def test_sync_does_not_create_duplicates():
    engine, db = create_test_session()

    try:
        adapter = MockCryptoAdapter()

        sync_algorithms(db, adapter)
        sync_algorithms(db, adapter)

        algorithms = db.query(PQCAlgorithm).all()

        assert len(algorithms) == 2

    finally:
        db.close()
        engine.dispose()