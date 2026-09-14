"""capss/scheme_execution/executors/dp_executor.py

Dynamic Pseudonym (DP) Executor.

Produces output_type="pseudonym" — NOT a SUCI. The output is a rotating
pseudonym that changes every epoch, preventing long-term subscriber tracking
without revealing the permanent identifier.

Construction:
  1. Compute the current epoch index:  epoch = int(now / epoch_seconds)
  2. Derive a per-epoch rotating key:
        period_key = HMAC-SHA256(shared_secret, epoch.to_bytes(8, 'big'))
  3. Compute the pseudonym:
        pseudonym = HMAC-SHA256(period_key, supi.encode('utf-8'))
     The result is a 32-byte value that is:
       - Deterministic for the same SUPI within the same epoch.
       - Indistinguishable from random across epochs.
       - Unlinkable without the shared_secret.

All operations use only Python stdlib (hashlib, hmac, secrets).

Terminology: this output is a *pseudonym*, not a SUCI.  It has no
encryption and carries no plaintext identifier — the pseudonym is
the only thing transmitted.
"""

from __future__ import annotations

import hashlib
import hmac
import time as _time_mod

from capss.scheme_execution.base import SchemeExecutor
from capss.scheme_execution.result import ExecutionResult

# Default epoch length in seconds (5 minutes)
_DEFAULT_EPOCH_SECONDS: int = 300

# HMAC output is always 32 bytes for SHA-256
_PSEUDONYM_SIZE_BYTES: int = 32

# The shared secret is 32 bytes; in a real deployment this would be
# provisioned out-of-band between UE and network.
_SHARED_SECRET_SIZE_BYTES: int = 32


class DPExecutor(SchemeExecutor):
    """Dynamic Pseudonym executor with HMAC-SHA256 rotating key.

    The pseudonym rotates every `epoch_seconds` seconds, providing
    temporal unlinkability: two observations in different epochs cannot
    be linked without the shared secret.

    Args:
        epoch_seconds: Length of each pseudonym epoch in seconds.
        shared_secret: 32-byte bytes used as HMAC key material.  If not
            provided, a stable random secret is generated at construction
            time (reused across calls to the same executor instance).
    """

    def __init__(
        self,
        epoch_seconds: int = _DEFAULT_EPOCH_SECONDS,
        shared_secret: bytes | None = None,
    ) -> None:
        import secrets as _secrets
        self._epoch_seconds = epoch_seconds
        self._shared_secret: bytes = (
            shared_secret
            if shared_secret is not None
            else _secrets.token_bytes(_SHARED_SECRET_SIZE_BYTES)
        )

    @property
    def scheme_name(self) -> str:
        return "DP"

    @property
    def output_type(self) -> str:
        return "pseudonym"

    @property
    def label(self) -> str:
        return (
            "Dynamic Pseudonym — rotating HMAC-SHA256 pseudonym. "
            "NOT a SUCI. Unlinkable across epochs without shared secret."
        )

    # ------------------------------------------------------------------
    # Public helper: verify pseudonym (for tests)
    # ------------------------------------------------------------------

    def verify_pseudonym(
        self, supi: str, pseudonym_bytes: bytes, epoch: int | None = None
    ) -> bool:
        """Return True if pseudonym_bytes matches the expected value for supi.

        Args:
            supi: The subscriber permanent identifier.
            pseudonym_bytes: The pseudonym to verify.
            epoch: Epoch index to use.  Defaults to current epoch.
        """
        if epoch is None:
            epoch = int(_time_mod.time() / self._epoch_seconds)
        period_key = self._derive_period_key(epoch)
        expected = hmac.new(
            period_key, supi.encode("utf-8"), hashlib.sha256
        ).digest()
        return hmac.compare_digest(pseudonym_bytes, expected)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _derive_period_key(self, epoch: int) -> bytes:
        """Derive the per-epoch HMAC key from the shared secret."""
        epoch_bytes = epoch.to_bytes(8, "big")
        return hmac.new(
            self._shared_secret, epoch_bytes, hashlib.sha256
        ).digest()

    def _run(self, ue_identity: dict) -> ExecutionResult:
        """Compute rotating pseudonym for this UE in the current epoch."""
        supi_str: str = ue_identity.get("supi", "")
        if not supi_str:
            raise ValueError("ue_identity must contain a non-empty 'supi' key")

        # Compute current epoch
        epoch = int(_time_mod.time() / self._epoch_seconds)

        # Derive per-epoch key and pseudonym
        period_key = self._derive_period_key(epoch)
        pseudonym = hmac.new(
            period_key, supi_str.encode("utf-8"), hashlib.sha256
        ).digest()

        return ExecutionResult(
            success=True,
            output_type=self.output_type,
            output_value=pseudonym,
            generation_time_ms=0.0,  # overwritten by base execute()
            key_size_bytes=_SHARED_SECRET_SIZE_BYTES,
            output_size_bytes=len(pseudonym),
            error=None,
            scheme_name=self.scheme_name,
            label=self.label,
            metadata={
                "epoch": epoch,
                "epoch_seconds": self._epoch_seconds,
                "hmac_algorithm": "SHA-256",
                "pseudonym_size_bytes": _PSEUDONYM_SIZE_BYTES,
            },
        )
