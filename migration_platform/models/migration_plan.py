import uuid

from sqlalchemy import (
    DateTime,
    ForeignKey,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from migration_platform.database import Base


class MigrationPlan(Base):
    __tablename__ = "migration_plans"

    migration_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    asset_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("assets.asset_id"),
        nullable=False,
        index=True,
    )

    recommendation_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("recommendations.recommendation_id"),
        nullable=False,
        index=True,
    )

    target_algorithm: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    target_mode: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="DRAFT",
    )

    approval_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="PENDING",
    )

    approved_by: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    approved_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    started_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    completed_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    def __repr__(self):
        return (
            f"<MigrationPlan("
            f"migration_id={self.migration_id!r}, "
            f"status={self.status!r}, "
            f"approval_status={self.approval_status!r})>"
        )