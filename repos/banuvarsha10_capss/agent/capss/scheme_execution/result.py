"""capss/scheme_execution/result.py

ExecutionResult — the uniform output contract for every SchemeExecutor.

All 7 executors return this same dataclass so that:
- Check 3 of assessment.py can compare generation_time_ms and
  output_size_bytes across any two schemes on an apples-to-apples basis.
- Callers can inspect output_type / label to understand WHAT was produced
  without having to know which executor was invoked.

TERMINOLOGY (enforced by output_type values):
  "suci"              ECIES only — real, standardised 3GPP SUCI.
  "suci_proposed_pqc" ML-KEM only — SUCI-shaped output, proposed
                      post-quantum extension, NOT 3GPP-standardised.
  "pseudonym"         DP — a rotating pseudonym, not a SUCI.
  "padded_payload"    AP — a padded payload with NO identity value.
  "zk_proof"          ZKP — a Schnorr zero-knowledge proof.
  "group_signature"   GS — a (simplified) group/ring signature.
  "ibe_ciphertext"    IBE — an identity-encrypted ciphertext.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# Allowed output_type values — kept as a frozenset so tests/assertions
# can import and validate against it without duplicating the list.
VALID_OUTPUT_TYPES: frozenset[str] = frozenset({
    "suci",
    "suci_proposed_pqc",
    "pseudonym",
    "padded_payload",
    "zk_proof",
    "group_signature",
    "ibe_ciphertext",
})


@dataclass
class ExecutionResult:
    """Uniform result returned by every SchemeExecutor.execute() call.

    Timing:
        generation_time_ms is measured via time.perf_counter() *inside*
        each executor's execute() method, covering only the cryptographic
        work itself (not any setup that happens at executor construction
        time). The same measurement approach is used in all 7 executors
        so comparisons are genuinely apples-to-apples.

    Size fields:
        key_size_bytes   — size of the relevant key material (scheme-
                           specific: ephemeral PK for ECIES, ciphertext
                           for ML-KEM, HMAC key for DP, etc.).
        output_size_bytes — len(output_value) when success=True; 0 on
                           failure.

    Failure:
        When success=False, output_value is None and error is populated.
        generation_time_ms reflects wall-clock time up to the point of
        failure (still >0 in almost all real cases).
    """

    success: bool
    """True if cryptographic operation completed without error."""

    output_type: str
    """One of VALID_OUTPUT_TYPES — describes WHAT was produced."""

    output_value: Optional[bytes]
    """Raw bytes of the Protected Identity Output (PIO), or None on failure."""

    generation_time_ms: float
    """Wall-clock time in milliseconds measured via time.perf_counter()."""

    key_size_bytes: int
    """Size of the key material used/produced (scheme-specific)."""

    output_size_bytes: int
    """len(output_value); 0 on failure."""

    error: Optional[str]
    """Human-readable error message; None on success."""

    scheme_name: str
    """Short name of the scheme (e.g. 'ECIES', 'ML-KEM', 'DP', ...)."""

    label: str
    """Human-readable label for this output, e.g.:
       'SUCI (3GPP TS 33.501, §C.4)'
       'PLACEHOLDER — timing/size representative only, NOT
        cryptographically real ML-KEM. Real liboqs-python was
        unavailable in this environment.'
    """

    metadata: dict = field(default_factory=dict)
    """Optional executor-specific metadata (e.g. curve, epoch, ring size)."""

    def __post_init__(self) -> None:
        if self.output_type not in VALID_OUTPUT_TYPES:
            raise ValueError(
                f"Invalid output_type {self.output_type!r}. "
                f"Must be one of: {sorted(VALID_OUTPUT_TYPES)}"
            )
        if self.success and self.output_value is not None:
            # Auto-correct output_size_bytes if caller didn't set it.
            if self.output_size_bytes == 0 and len(self.output_value) > 0:
                object.__setattr__(self, "output_size_bytes", len(self.output_value))

    @property
    def is_placeholder(self) -> bool:
        """True if this result is a timing/size placeholder, not real crypto."""
        return "PLACEHOLDER" in self.label
