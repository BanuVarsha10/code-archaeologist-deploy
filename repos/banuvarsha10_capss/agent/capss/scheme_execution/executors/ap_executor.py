"""capss/scheme_execution/executors/ap_executor.py

Adaptive Padding (AP) Executor.

Produces output_type="padded_payload" — NOT a SUCI. There is NO
identity value in this output at all. Adaptive Padding works at the
traffic-shaping level: it pads a payload to a discrete bucket size so
that an observer cannot infer the original payload length from the
wire-level size.

IMPORTANT TERMINOLOGY: the padded_payload output contains NO subscriber
identifier. AP does not encrypt or conceal an identity — it shapes
traffic to prevent size-based fingerprinting. This makes it
fundamentally different from all other six schemes.

Construction (PADME-inspired bucket rounding):
  The PADME (Padded Adaptive Data MEssaging) scheme rounds up every
  message to the next "bucket boundary" to limit what an observer can
  infer about the true payload length.

  Bucket boundaries used here:
    - Minimum size: 64 bytes (anything smaller is padded to 64)
    - Above minimum: round up to the next power of 2
    - Optional: for large payloads (>= 4096 bytes) use 4096-byte buckets

  Padding bytes: filled with zeros.  In a real deployment, CSPRNG-filled
  padding would be used; zeros are used here to keep the executor
  dependency-free (stdlib only).

  Framing: the output is:
    [2-byte original_length] [payload_bytes] [zero_padding]
  so the receiver can strip padding by reading original_length.

All operations use only Python stdlib.
"""

from __future__ import annotations

import struct

from capss.scheme_execution.base import SchemeExecutor
from capss.scheme_execution.result import ExecutionResult

# Minimum padded output size (bytes)
_MIN_PADDED_SIZE: int = 64
# Threshold above which we switch to fixed large-block rounding
_LARGE_BLOCK_THRESHOLD: int = 4096
_LARGE_BLOCK_SIZE: int = 4096
# Header size: 2 bytes for original_length
_HEADER_SIZE: int = 2


def _padme_bucket(payload_len: int) -> int:
    """Return the PADME bucket size for a given payload length.

    Rules:
      - payload_len == 0: returns MIN_PADDED_SIZE (must always have some output)
      - payload_len + header <= MIN: returns MIN_PADDED_SIZE
      - payload_len + header >= LARGE_BLOCK_THRESHOLD: returns ceiling multiple
        of _LARGE_BLOCK_SIZE
      - otherwise: next power of 2 that fits (payload + header)
    """
    total = payload_len + _HEADER_SIZE
    if total <= _MIN_PADDED_SIZE:
        return _MIN_PADDED_SIZE
    if total >= _LARGE_BLOCK_THRESHOLD:
        # Round up to next multiple of _LARGE_BLOCK_SIZE
        blocks = (total + _LARGE_BLOCK_SIZE - 1) // _LARGE_BLOCK_SIZE
        return blocks * _LARGE_BLOCK_SIZE
    # Next power of 2 >= total
    bucket = 1
    while bucket < total:
        bucket <<= 1
    return bucket


class APExecutor(SchemeExecutor):
    """Adaptive Padding executor (PADME bucket-rounding).

    Output is a padded_payload with NO identity value.  The purpose
    is traffic-analysis resistance through size normalisation, not
    identity concealment.

    Args:
        default_payload: Default bytes to pad when ue_identity contains
            no 'payload' key.  Defaults to b'' (empty — results in
            minimum-size padded output).
    """

    def __init__(self, default_payload: bytes = b"") -> None:
        self._default_payload = default_payload

    @property
    def scheme_name(self) -> str:
        return "AP"

    @property
    def output_type(self) -> str:
        return "padded_payload"

    @property
    def label(self) -> str:
        return (
            "Adaptive Padding (PADME bucket-rounding). "
            "NOT a SUCI — output contains NO subscriber identity. "
            "Provides traffic-analysis resistance via size normalisation."
        )

    def _run(self, ue_identity: dict) -> ExecutionResult:
        """Pad the payload to a PADME bucket boundary.

        ue_identity may contain:
          'payload' (bytes): data to pad.  If absent, uses default_payload.
          'supi' (str): accepted but not embedded in output.
        """
        raw_payload: bytes = ue_identity.get("payload", self._default_payload)
        if isinstance(raw_payload, str):
            raw_payload = raw_payload.encode("utf-8")
        if not isinstance(raw_payload, (bytes, bytearray)):
            raise TypeError(
                f"'payload' must be bytes, got {type(raw_payload).__name__}"
            )
        raw_payload = bytes(raw_payload)

        # Compute target bucket size
        bucket_size = _padme_bucket(len(raw_payload))

        # Build padded output: [2-byte len] [payload] [zero padding]
        original_len = len(raw_payload)
        header = struct.pack(">H", original_len)
        body = raw_payload
        padding_needed = bucket_size - _HEADER_SIZE - original_len
        if padding_needed < 0:
            # Should not happen given correct _padme_bucket, but guard
            padding_needed = 0
        padded = header + body + b"\x00" * padding_needed

        return ExecutionResult(
            success=True,
            output_type=self.output_type,
            output_value=padded,
            generation_time_ms=0.0,  # overwritten by base execute()
            key_size_bytes=0,  # AP uses no key material
            output_size_bytes=len(padded),
            error=None,
            scheme_name=self.scheme_name,
            label=self.label,
            metadata={
                "original_payload_bytes": original_len,
                "padded_size_bytes": len(padded),
                "bucket_size": bucket_size,
                "padding_added_bytes": padding_needed,
                "padding_scheme": "PADME-power-of-2",
            },
        )

    def strip_padding(self, padded: bytes) -> bytes:
        """Extract the original payload from a padded output."""
        if len(padded) < _HEADER_SIZE:
            raise ValueError("Padded payload too short to contain header")
        (original_len,) = struct.unpack_from(">H", padded, 0)
        return padded[_HEADER_SIZE: _HEADER_SIZE + original_len]
