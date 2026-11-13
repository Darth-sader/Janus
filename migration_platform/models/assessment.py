import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, JSON, String, func
from sqlalchemy.orm import Mapped, mapped_column

from migration_platform.database import Base


class Assessment(Base):
    """Stores an asset's five-dimensional migration assessment."""

    __tablename__ = "assessments"

    assessment_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.asset_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    security_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )

    compatibility_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )

    performance_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )

    lifecycle_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )

    migration_priority: Mapped[str] = mapped_column(
        String(30),
        nullable=False
    )

    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict
    )

    assessed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
