import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from migration_platform.database import Base


class Recommendation(Base):
    """Stores explainable migration recommendations for infrastructure assets."""

    __tablename__ = "recommendations"

    recommendation_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.asset_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.assessment_id", ondelete="RESTRICT"),
        nullable=False
    )

    current_algorithm: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True
    )

    target_algorithm: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True
    )

    migration_mode: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True
    )

    outcome: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )

    priority: Mapped[str] = mapped_column(
        String(30),
        nullable=False
    )

    reasoning: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )

    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
