import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from migration_platform.database import Base


class CryptoConfig(Base):
    """Stores the cryptographic configuration currently used by an asset."""

    __tablename__ = "crypto_configs"

    config_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.asset_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    algorithm: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )

    key_size: Mapped[int | None] = mapped_column(nullable=True)

    signature_scheme: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="ACTIVE"
    )

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
