from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from migration_platform.database import Base


class PQCAlgorithm(Base):
    """Stores algorithm capability snapshots supplied by the crypto layer."""

    __tablename__ = "pqc_algorithms"

    algorithm_id: Mapped[str] = mapped_column(
        String(100),
        primary_key=True
    )

    name: Mapped[str] = mapped_column(
        String(150),
        nullable=False
    )

    family: Mapped[str] = mapped_column(
        String(30),
        nullable=False
    )

    standard: Mapped[str] = mapped_column(
        String(150),
        nullable=False
    )

    security_level: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )

    key_size: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True
    )

    signature_size: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True
    )

    implementation: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True
    )

    quantum_vulnerable: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False
    )

    implemented: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False
    )

    notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    last_synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
