import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from migration_platform.database import Base


class Asset(Base):
    """Represents a critical infrastructure asset."""

    __tablename__ = "assets"

    asset_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    asset_type: Mapped[str] = mapped_column(
        "type",
        String(100),
        nullable=False
    )

    criticality: Mapped[str] = mapped_column(
        String(30),
        nullable=False
    )

    firmware_version: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True
    )

    operational_lifetime: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True
    )

    update_capability: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True
    )

    protocol: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )

    def __repr__(self) -> str:
        return (
            f"<Asset(asset_id='{self.asset_id}', "
            f"type='{self.asset_type}', "
            f"criticality='{self.criticality}')>"
        )
