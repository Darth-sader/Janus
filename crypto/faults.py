"""Cryptographic fault isolation and fail-closed behavior (Tier 1.5).

Semantics (normative for the whole crypto layer):

* **No partial artifacts** - if any required component of a multi-part
  operation fails, the operation fails as a whole; callers never
  receive a seemingly-successful object missing a security component.
* **Fail closed** - a failed, crashed, timed-out or unhealthy required
  component can never degrade into a classical-only or
  single-component "success".  Verification problems are reported as
  non-acceptance, never as acceptance with a warning.
* **Resource limits** - oversized messages, signatures, keys and
  serialized structures are rejected *before* cryptographic processing.
* **Normalized external errors, detailed internal diagnostics** -
  exceptions crossing the package boundary carry exception *type*
  names only, never payloads; the detailed reason travels in
  structured results (e.g. ``ComponentResult.detail``) where it is
  logged on purpose, and never contains key material.
* **Idempotent retries** - retries of interrupted artifact-producing
  operations must not duplicate or diverge (see
  :class:`OperationJournal`).
"""

from __future__ import annotations

import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from pathlib import Path

from crypto.errors import ResourceLimitExceededError

#: default resource limits for the crypto layer
DEFAULT_MAX_MESSAGE_BYTES = 1_048_576        # 1 MiB message payload
DEFAULT_MAX_SERIALIZED_BYTES = 262_144       # 256 KiB serialized object
DEFAULT_MAX_KEY_BYTES = 65_536               # 64 KiB key material
DEFAULT_MAX_SIGNATURE_BYTES = 65_536         # 64 KiB signature blob


@dataclass(frozen=True)
class ResourceLimits:
    """Configurable input-size limits (fail-closed boundaries)."""

    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    max_serialized_bytes: int = DEFAULT_MAX_SERIALIZED_BYTES
    max_key_bytes: int = DEFAULT_MAX_KEY_BYTES
    max_signature_bytes: int = DEFAULT_MAX_SIGNATURE_BYTES


DEFAULT_LIMITS = ResourceLimits()


def check_message_size(message: bytes, limits: ResourceLimits | None = None) -> bytes:
    limits = limits or DEFAULT_LIMITS
    if not isinstance(message, (bytes, bytearray)):
        raise ResourceLimitExceededError("message must be bytes")
    message = bytes(message)
    if len(message) > limits.max_message_bytes:
        raise ResourceLimitExceededError(
            f"message exceeds limit ({len(message)} > {limits.max_message_bytes} bytes); refused before signing"
        )
    return message


def check_serialized_size(data: bytes, limits: ResourceLimits | None = None) -> bytes:
    limits = limits or DEFAULT_LIMITS
    if not isinstance(data, (bytes, bytearray)):
        raise ResourceLimitExceededError("serialized input must be bytes")
    data = bytes(data)
    if len(data) > limits.max_serialized_bytes:
        raise ResourceLimitExceededError(
            f"serialized input exceeds limit ({len(data)} > {limits.max_serialized_bytes} bytes)"
        )
    return data


def check_key_size(data: bytes, limits: ResourceLimits | None = None) -> bytes:
    limits = limits or DEFAULT_LIMITS
    if len(data) > limits.max_key_bytes:
        raise ResourceLimitExceededError(f"key material exceeds limit ({len(data)} bytes)")
    return data


def check_signature_size(data: bytes, limits: ResourceLimits | None = None) -> bytes:
    limits = limits or DEFAULT_LIMITS
    if len(data) > limits.max_signature_bytes:
        raise ResourceLimitExceededError(
            f"signature exceeds limit ({len(data)} > {limits.max_signature_bytes} bytes)"
        )
    return data


def sanitize_external_error(exc: BaseException) -> str:
    """Normalized external error text: exception *type* only.

    Detailed reasons are the caller's business and travel through
    structured diagnostics (ComponentResult.detail); anything that
    crosses a trust boundary gets a type name, so no library-internal
    payload (which could in principle echo input material) escapes.
    """
    return f"external error ({type(exc).__name__})"


def verify_fail_closed(operation, timeout_s: float | None = None):
    """Run a verification operation; convert *any* failure mode -
    exception, timeout, crash - into a non-accepting outcome.

    Returns ``(result, diagnostic)``.  On timeout or crash the result is
    the caller's fail-closed value (verification callers use ``False``;
    component-diagnostic callers use a non-VERIFIED status).

    Note on timeouts: a stuck native call cannot be force-killed inside
    one process, so the timed-out worker is abandoned, not joined - the
    *decision* is still fail-closed and returned on time.
    """
    if timeout_s is None:
        try:
            return operation(), None
        except Exception as exc:  # noqa: BLE001 - fail-closed normalization
            return None, sanitize_external_error(exc)
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="pqc-verify")
    try:
        future = executor.submit(operation)
        try:
            return future.result(timeout=timeout_s), None
        except FutureTimeoutError:
            future.cancel()
            return None, f"verification timed out after {timeout_s}s (fail-closed)"
        except Exception as exc:  # noqa: BLE001
            return None, sanitize_external_error(exc)
    finally:
        executor.shutdown(wait=False)


class OperationJournal:
    """Idempotency guard for artifact-producing operations.

    Interrupted operations (crash between signing and recording) are the
    classic way retries create duplicate or inconsistent migration
    artifacts.  The journal records ``(operation_type, request_digest)
    -> result_digest`` so a retry with the same request returns the
    original result instead of producing a second artifact.
    """

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self._path = Path(path) if path is not None else None
        self._lock = threading.RLock()
        self._records: dict[str, dict] = {}
        if self._path is not None and self._path.exists():
            try:
                self._records = json.loads(self._path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001 - corrupt journal: start clean but never reuse stale entries
                self._records = {}

    # ------------------------------------------------------------------ #
    @staticmethod
    def key(operation_type: str, request_digest: str) -> str:
        return f"{operation_type}:{request_digest}"

    def lookup(self, operation_type: str, request_digest: str) -> dict | None:
        with self._lock:
            return self._records.get(self.key(operation_type, request_digest))

    def begin(self, operation_type: str, request_digest: str) -> bool:
        """Claim an operation slot; returns False if already claimed."""
        with self._lock:
            key = self.key(operation_type, request_digest)
            if key in self._records:
                return False
            self._records[key] = {"status": "PENDING"}
            self._persist()
            return True

    def complete(self, operation_type: str, request_digest: str, result_digest: str) -> None:
        with self._lock:
            self._records[self.key(operation_type, request_digest)] = {
                "status": "COMPLETED",
                "result_digest": result_digest,
            }
            self._persist()

    # ------------------------------------------------------------------ #
    def execute(self, operation_type: str, request_digest: str, producer) -> tuple[object, bool]:
        """Run ``producer()`` at most once per request; retries reuse the
        completed result.  Returns ``(result, reused)``."""
        existing = self.lookup(operation_type, request_digest)
        if existing is not None and existing.get("status") == "COMPLETED":
            return existing["result_digest"], True
        if not self.begin(operation_type, request_digest):
            # claimed but not completed: an earlier attempt is in flight
            # or was interrupted - do not silently duplicate it
            raise RuntimeError(
                f"operation {operation_type}/{request_digest[:12]} already in progress or interrupted; "
                "resolve the pending attempt before retrying"
            )
        try:
            result = producer()
        except Exception:
            # leave the PENDING marker: an interrupted operation must be
            # resolved explicitly, not auto-retried into a duplicate
            raise
        self.complete(operation_type, request_digest, result)
        return result, False

    # ------------------------------------------------------------------ #
    def _persist(self) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._records, sort_keys=True, indent=1), encoding="utf-8")
