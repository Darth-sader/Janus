"""Versioned canonical cryptographic encoding (Tier 1.3).

Every structure this layer signs is encoded through this module.  The
encoding is **fully specified, injective and deterministic**: two
equivalent logical inputs always produce the same bytes, and different
logical inputs never collide.  That is what makes "the exact bytes that
were signed" a well-defined notion.

Format version ``HPKI-CANON-1`` (wire description)
---------------------------------------------------

::

    magic            12 bytes  b"HPKI-CANON-1"
    context          u16 length + UTF-8 purpose label (see contexts.py)
    field_count      u32
    then, per field (ordered by field name, UTF-8 byte order):
        name         u16 length + UTF-8
        type_tag     u8   (see _TAG_*)
        value        type-specific:
            BYTES    u32 length + raw
            STR      u32 length + NFC-normalized UTF-8
            INT      u32 length + decimal ASCII (arbitrary size, signed)
            BOOL     u8 (0/1)
            DATETIME u32 length + ISO-8601 UTC ASCII
            NULL     (empty)
            LIST     u32 count, then per element: u32 length + encoded element
            DICT     u32 count, then per entry (sorted keys):
                             u32 length + encoded entry

Length-prefixing everywhere removes delimiter ambiguity; fixed field
ordering removes reordering ambiguity; NFC removes Unicode-composition
ambiguity; the leading magic+version makes the encoding itself
versioned and evolvable.

The module also provides :func:`strict_json_loads` - JSON parsing that
**rejects duplicate keys** - for every place that parses signed JSON
(hybrid signatures, certificate objects): a duplicate field must never
be silently resolved to "last one wins" by the parser.
"""

from __future__ import annotations

import json
import unicodedata
from datetime import datetime, timezone
from typing import Any, Mapping

from crypto.errors import ResourceLimitExceededError, SerializationError

ENCODING_VERSION = 1
_MAGIC = b"HPKI-CANON-1"

# type tags
_TAG_BYTES = 0x01
_TAG_STR = 0x02
_TAG_INT = 0x03
_TAG_BOOL = 0x04
_TAG_DATETIME = 0x05
_TAG_NULL = 0x06
_TAG_LIST = 0x07
_TAG_DICT = 0x08

_TYPE_NAMES = {
    _TAG_BYTES: "bytes",
    _TAG_STR: "str",
    _TAG_INT: "int",
    _TAG_BOOL: "bool",
    _TAG_DATETIME: "datetime",
    _TAG_NULL: "null",
    _TAG_LIST: "list",
    _TAG_DICT: "dict",
}


def strict_json_loads(data: bytes | str) -> Any:
    """JSON parsing that rejects duplicate object keys.

    Used for every signed structure received from outside; a duplicated
    field in a signed object is an attack (or a bug), never a
    "last value wins" situation.
    """

    def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict:
        result: dict = {}
        for key, value in pairs:
            if key in result:
                raise SerializationError(f"duplicate field {key!r} in JSON object")
            result[key] = value
        return result

    try:
        if isinstance(data, (bytes, bytearray)):
            data = bytes(data).decode("utf-8")
        return json.loads(data, object_pairs_hook=_no_duplicates)
    except SerializationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SerializationError(f"invalid JSON ({type(exc).__name__})") from None


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def _check_len(value: int, what: str, limits: "EncodingLimits") -> int:
    if value > limits.max_string_bytes:
        raise ResourceLimitExceededError(f"{what} exceeds limit ({value} > {limits.max_string_bytes} bytes)")
    return value


class EncodingLimits:
    """Resource limits applied while encoding/decoding (fail-closed)."""

    def __init__(
        self,
        *,
        max_total_bytes: int = 262_144,
        max_string_bytes: int = 16_384,
        max_fields: int = 64,
        max_depth: int = 8,
        max_elements: int = 256,
    ) -> None:
        self.max_total_bytes = max_total_bytes
        self.max_string_bytes = max_string_bytes
        self.max_fields = max_fields
        self.max_depth = max_depth
        self.max_elements = max_elements


DEFAULT_LIMITS = EncodingLimits()


def _validate_key(name: str) -> None:
    if not isinstance(name, str) or not name:
        raise SerializationError("field names must be non-empty strings")
    if not name.isascii() or not (name.replace("_", "").replace("-", "").isalnum()):
        raise SerializationError(f"field name {name!r} must be ASCII alphanumeric plus _ or -")


def _encode_value(value: Any, depth: int, limits: EncodingLimits) -> bytes:
    if depth > limits.max_depth:
        raise ResourceLimitExceededError(f"encoding exceeds nesting depth {limits.max_depth}")

    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        _check_len(len(raw), "bytes field", limits)
        return bytes([_TAG_BYTES]) + _u32(len(raw)) + raw
    if isinstance(value, str):
        normalized = unicodedata.normalize("NFC", value).encode("utf-8")
        _check_len(len(normalized), "string field", limits)
        return bytes([_TAG_STR]) + _u32(len(normalized)) + normalized
    if isinstance(value, bool):  # before int: bool is an int subclass
        return bytes([_TAG_BOOL, 1 if value else 0])
    if isinstance(value, int):
        text = str(value).encode("ascii")
        _check_len(len(text), "integer field", limits)
        return bytes([_TAG_INT]) + _u32(len(text)) + text
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise SerializationError("datetime fields must be timezone-aware")
        text = value.astimezone(timezone.utc).isoformat().encode("ascii")
        return bytes([_TAG_DATETIME]) + _u32(len(text)) + text
    if value is None:
        return bytes([_TAG_NULL])
    if isinstance(value, (list, tuple)):
        if len(value) > limits.max_elements:
            raise ResourceLimitExceededError(f"list exceeds {limits.max_elements} elements")
        elements = b"".join(_u32(len(enc)) + enc for enc in (_encode_value(v, depth + 1, limits) for v in value))
        return bytes([_TAG_LIST]) + _u32(len(value)) + elements
    if isinstance(value, Mapping):
        if len(value) > limits.max_elements:
            raise ResourceLimitExceededError(f"dict exceeds {limits.max_elements} entries")
        parts = []
        for key in sorted(value, key=lambda k: unicodedata.normalize("NFC", str(k)).encode("utf-8")):
            _validate_key(str(key))
            entry = _u16(len(key.encode("utf-8"))) + key.encode("utf-8") + _encode_value(
                value[key], depth + 1, limits
            )
            parts.append(_u32(len(entry)) + entry)
        return bytes([_TAG_DICT]) + _u32(len(value)) + b"".join(parts)
    raise SerializationError(f"unsupported field type {type(value).__name__}")


def encode_struct(context: str, fields: Mapping[str, Any], limits: EncodingLimits | None = None) -> bytes:
    """Encode a signed structure: versioned magic + purpose context +
    deterministic field encoding.

    ``context`` must be a registered domain-separation label
    (:mod:`crypto.encoding.contexts`) - this is what makes a signature
    from one purpose unusable in another.
    """
    from .contexts import validate_context

    validate_context(context)
    limits = limits or DEFAULT_LIMITS
    if not isinstance(fields, Mapping):
        raise SerializationError("fields must be a mapping")
    if len(fields) > limits.max_fields:
        raise ResourceLimitExceededError(f"structure exceeds {limits.max_fields} fields")
    for name in fields:
        _validate_key(name)

    out = bytearray(_MAGIC)
    ctx = context.encode("ascii")
    out += _u16(len(ctx)) + ctx
    out += _u32(len(fields))
    for name in sorted(fields, key=lambda n: n.encode("utf-8")):
        name_bytes = name.encode("utf-8")
        out += _u16(len(name_bytes)) + name_bytes
        out += _encode_value(fields[name], 1, limits)
    if len(out) > limits.max_total_bytes:
        raise ResourceLimitExceededError(f"encoded structure exceeds {limits.max_total_bytes} bytes")
    return bytes(out)


# --------------------------------------------------------------------- #
# decoder (round-trip verification + test vectors)
# --------------------------------------------------------------------- #
class _Reader:
    def __init__(self, data: bytes, limits: EncodingLimits) -> None:
        self.data = data
        self.pos = 0
        self.limits = limits

    def take(self, n: int, what: str) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise SerializationError(f"truncated encoding while reading {what}")
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def u8(self) -> int:
        return self.take(1, "u8")[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2, "u16"), "big")

    def u32(self) -> int:
        return int.from_bytes(self.take(4, "u32"), "big")

    def at_end(self) -> bool:
        return self.pos == len(self.data)


def _decode_value(reader: _Reader, depth: int) -> Any:
    if depth > reader.limits.max_depth:
        raise ResourceLimitExceededError(f"decoding exceeds nesting depth {reader.limits.max_depth}")
    tag = reader.u8()
    if tag == _TAG_BYTES:
        length = reader.u32()
        _check_len(length, "bytes field", reader.limits)
        return reader.take(length, "bytes value")
    if tag == _TAG_STR:
        length = reader.u32()
        _check_len(length, "string field", reader.limits)
        return reader.take(length, "string value").decode("utf-8")
    if tag == _TAG_INT:
        length = reader.u32()
        _check_len(length, "integer field", reader.limits)
        return int(reader.take(length, "integer value").decode("ascii"))
    if tag == _TAG_BOOL:
        return bool(reader.u8())
    if tag == _TAG_DATETIME:
        length = reader.u32()
        return datetime.fromisoformat(reader.take(length, "datetime value").decode("ascii"))
    if tag == _TAG_NULL:
        return None
    if tag == _TAG_LIST:
        count = reader.u32()
        if count > reader.limits.max_elements:
            raise ResourceLimitExceededError("list exceeds element limit")
        out = []
        for _ in range(count):
            size = reader.u32()
            out.append(_decode_value(_Reader(reader.take(size, "list element"), reader.limits), depth + 1))
        return out
    if tag == _TAG_DICT:
        count = reader.u32()
        if count > reader.limits.max_elements:
            raise ResourceLimitExceededError("dict exceeds entry limit")
        out: dict = {}
        for _ in range(count):
            size = reader.u32()
            entry = _Reader(reader.take(size, "dict entry"), reader.limits)
            name = entry.take(entry.u16(), "field name").decode("utf-8")
            if name in out:
                raise SerializationError(f"duplicate field {name!r} in encoded dict")
            out[name] = _decode_value(entry, depth + 1)
            if not entry.at_end():
                raise SerializationError("trailing bytes in dict entry")
        return out
    raise SerializationError(f"unknown type tag 0x{tag:02x}")


def decode_struct(data: bytes, limits: EncodingLimits | None = None) -> tuple[str, dict]:
    """Decode bytes produced by :func:`encode_struct`; returns
    ``(context, fields)``.  Raises SerializationError on any deviation
    from the format (wrong magic, truncation, trailing bytes)."""
    limits = limits or DEFAULT_LIMITS
    if not isinstance(data, (bytes, bytearray)):
        raise SerializationError("encoded structure must be bytes")
    data = bytes(data)
    if len(data) > limits.max_total_bytes:
        raise ResourceLimitExceededError(f"encoded structure exceeds {limits.max_total_bytes} bytes")
    reader = _Reader(data, limits)
    magic = reader.take(len(_MAGIC), "magic")
    if magic != _MAGIC:
        raise SerializationError("not an HPKI-CANON structure (bad magic)")
    ctx = reader.take(reader.u16(), "context").decode("ascii")
    from .contexts import validate_context

    validate_context(ctx)
    count = reader.u32()
    if count > limits.max_fields:
        raise ResourceLimitExceededError(f"structure exceeds {limits.max_fields} fields")
    fields: dict = {}
    for _ in range(count):
        name = reader.take(reader.u16(), "field name").decode("utf-8")
        if name in fields:
            raise SerializationError(f"duplicate field {name!r}")
        fields[name] = _decode_value(reader, 1)
    if not reader.at_end():
        raise SerializationError("trailing bytes after encoded structure")
    return ctx, fields


# --------------------------------------------------------------------- #
# schema validation for signed structures
# --------------------------------------------------------------------- #
def validate_schema(
    fields: Mapping[str, Any],
    schema: Mapping[str, tuple],
    *,
    allow_unknown_fields: bool = False,
) -> None:
    """Validate fields against a schema ``{name: (type, required)}``.

    Unknown mandatory fields cannot exist by definition; what this
    rejects is (a) missing required fields and (b) unknown fields in
    strict mode - an attacker adding a field to a signed structure must
    not be able to smuggle semantics past a verifier that ignores it.
    """
    for name, (_type, required) in schema.items():
        if required and name not in fields:
            raise SerializationError(f"missing required field {name!r}")
    if not allow_unknown_fields:
        unknown = sorted(set(fields) - set(schema))
        if unknown:
            raise SerializationError(f"unknown fields not permitted: {unknown}")
    for name, value in fields.items():
        if name in schema:
            expected = schema[name][0]
            if expected is not None and not isinstance(value, expected):
                raise SerializationError(
                    f"field {name!r} has type {type(value).__name__}, expected {getattr(expected, '__name__', expected)}"
                )
