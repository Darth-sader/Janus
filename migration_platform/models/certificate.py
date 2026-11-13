import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from migration_platform.database import Base


class Certificate(Base):
    """Stores certificate metadata and links it to a Janus asset."""

    __tablename__ = "certificates"

    certificate_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )

    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.asset_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # ID assigned by Person 2's CertificateManager
    external_cert_id: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False
    )

    serial_number: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True
    )

    issuer: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True
    )

    subject: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True
    )

    public_key_algorithm: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True
    )

    signature_algorithm: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True
    )

    mode: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True
    )

    issued_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="ACTIVE"
    )

    expired: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True
    )

    synced_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
