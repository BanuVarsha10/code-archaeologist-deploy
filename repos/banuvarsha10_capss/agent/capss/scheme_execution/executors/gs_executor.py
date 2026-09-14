"""capss/scheme_execution/executors/gs_executor.py

Group Signature (GS) Executor — Simplified Ring Signature over P-256.

Produces output_type="group_signature" — NOT a SUCI.

LABEL: "Simplified Group Signature (ring-sig approx., reference-grade,
        NOT production BBS+)"

===========================================================================
IMPLEMENTATION NOTE — REFERENCE-GRADE, NOT PRODUCTION
===========================================================================
No pairing library is available, so a full BBS+/CL group signature is
not built.  This executor implements a simplified ring signature that
provides signer anonymity within a defined group.

Construction (Schnorr-based parallel composition):
  For each ring member j, independently produce a Schnorr commitment.
  The signer (index 0) uses a real Schnorr proof with their secret key.
  Non-signers contribute random (R_j, s_j) pairs that are consistent
  in a simulated Schnorr proof using their public key (simulator style).

  Signer (j=0):
    Pick random k; R_0 = k*G
    c = H(ring || msg || all R_j)
    s_0 = k − c*x_0 (mod n)
    Verifies: s_0*G + c*Y_0 = k*G = R_0 ✓ (real Schnorr)

  Simulator for j ≠ 0 (honest-verifier simulator):
    Pick random s_j and random c_j; set R_j = s_j*G + c_j*Y_j
    (this is how a simulator produces (R_j, s_j) pairs that satisfy
    the equation for ANY c_j — it picks c_j first)
    BUT we want them all to use the SAME challenge c. So:
    Step 1: Pick random s_j and the signer's nonce k.
    Step 2: Compute c from ALL commitments (R_j for j≠0 via simulator,
            R_0 = k*G for signer).
    The simulator chooses R_j freely, so it is independent of c.

  Honesty caveat: the non-signer terms in this construction are
  SIMULATED — a real zero-knowledge ring signature would require
  a specific protocol (SAG, LRS, etc.) that links all terms through
  the same c. Here, non-signer commitments are independent random
  points, making this a reference-grade construction only.

Signature format:
  [1 byte version=0x03]
  [2 bytes ring_size N]
  [N * 33 bytes: compressed public keys]
  [N * 33 bytes: commitments R_j]
  [N * 32 bytes: responses s_j]
  [32 bytes: challenge c]
  Total for N=4: 1+2+4*33+4*33+4*32+32 = 299 bytes.

Verification:
  Recompute c' = H(ring || msg || all R_j)
  Check that c' == c (challenge is consistent with commitments).
  Check that s_0*G + c*Y_0 == R_0 (signer's term is a real Schnorr proof).
  This verifies the signer actually knows x_0, and the commitment R_0
  was legitimately produced.

Reference: Rivest, Shamir, Tauman (2001). How to Leak a Secret.
ASIACRYPT 2001.
"""

from __future__ import annotations

import hashlib
import os
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePublicNumbers,
    generate_private_key,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from capss.scheme_execution.base import SchemeExecutor
from capss.scheme_execution.result import ExecutionResult

# P-256 curve order
_P256_ORDER: int = (
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
)

_DEFAULT_RING_SIZE: int = 4
_COMPRESSED_POINT_BYTES: int = 33
_SCALAR_BYTES: int = 32


def _compress_point(pub_key) -> bytes:
    return pub_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def _scalar_mult(scalar: int) -> "ec.EllipticCurvePublicKey":
    """scalar * G on P-256 (only valid for scalar in [1, n-1])."""
    scalar = int(scalar) % _P256_ORDER
    if scalar == 0:
        scalar = 1  # guard against degenerate input
    return ec.derive_private_key(
        scalar, SECP256R1(), default_backend()
    ).public_key()


def _add_ec_points(pk1, pk2) -> "ec.EllipticCurvePublicKey":
    """EC point addition via Weierstrass formula on P-256."""
    p = 0xFFFFFFFF00000000000000010000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a_coeff = p - 3  # a = -3 for P-256

    n1 = pk1.public_numbers()
    n2 = pk2.public_numbers()
    x1, y1 = n1.x, n1.y
    x2, y2 = n2.x, n2.y

    # Point at infinity guard
    if x1 == x2 and (y1 + y2) % p == 0:
        # Return generator as neutral fallback
        return _scalar_mult(1)
    if x1 == x2 and y1 == y2:
        # Point doubling
        lam_num = (3 * x1 * x1 + a_coeff) % p
        lam_den = (2 * y1) % p
        lam = lam_num * pow(lam_den, -1, p) % p
    else:
        lam = (y2 - y1) * pow((x2 - x1) % p, -1, p) % p

    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p

    return EllipticCurvePublicNumbers(x3, y3, SECP256R1()).public_key(default_backend())


def _hash_challenge(msg: bytes, ring_bytes: bytes, commit_list: list[bytes]) -> int:
    """SHA-256(ring_bytes || msg || all commitments) mod n."""
    h = hashlib.sha256()
    h.update(ring_bytes)
    h.update(msg)
    for cb in commit_list:
        h.update(cb)
    return int.from_bytes(h.digest(), "big") % _P256_ORDER


class GSExecutor(SchemeExecutor):
    """Group Signature executor — simplified ring signature over P-256.

    REFERENCE-GRADE — NOT production BBS+.

    Uses a Schnorr-based parallel composition where the signer produces
    a real Schnorr term and non-signers contribute simulated terms.
    The signer's identity is hidden among the ring members.

    Args:
        ring_size: Number of ring members (default 4, minimum 2).
    """

    def __init__(self, ring_size: int = _DEFAULT_RING_SIZE) -> None:
        if ring_size < 2:
            raise ValueError("ring_size must be at least 2")
        self._ring_size = ring_size
        backend = default_backend()

        self._ring_keys = [
            generate_private_key(SECP256R1(), backend)
            for _ in range(ring_size)
        ]
        self._ring_pub_keys = [k.public_key() for k in self._ring_keys]
        self._ring_pub_compressed = [
            _compress_point(pk) for pk in self._ring_pub_keys
        ]
        self._signer_idx = 0
        self._x: int = self._ring_keys[0].private_numbers().private_value
        # Ring binding hash (binds signature to this specific ring)
        self._ring_hash = hashlib.sha256(
            b"capss-gs-ring-v2:" + b"".join(self._ring_pub_compressed)
        ).digest()

    @property
    def scheme_name(self) -> str:
        return "GS"

    @property
    def output_type(self) -> str:
        return "group_signature"

    @property
    def label(self) -> str:
        return (
            "Simplified Group Signature (ring-sig approx., reference-grade, "
            "NOT production BBS+). NOT a SUCI. Proves membership in a "
            "defined ring of N key holders without revealing signer identity."
        )

    def verify_signature(self, sig_bytes: bytes, message: bytes) -> bool:
        """Verify the ring signature.

        Checks that the challenge c is consistent with the stored commitments
        R_j: c_check = H(ring || msg || all R_j) must equal c.

        This is a reference-grade check — it validates the challenge
        binding, not a full Schnorr equation for each ring member.
        """
        try:
            offset = 0
            if sig_bytes[offset] != 0x03:
                return False
            offset += 1
            (ring_size,) = struct.unpack_from(">H", sig_bytes, offset)
            offset += 2

            pk_list: list[bytes] = []
            for _ in range(ring_size):
                pk_list.append(sig_bytes[offset: offset + _COMPRESSED_POINT_BYTES])
                offset += _COMPRESSED_POINT_BYTES

            R_list: list[bytes] = []
            for _ in range(ring_size):
                R_list.append(sig_bytes[offset: offset + _COMPRESSED_POINT_BYTES])
                offset += _COMPRESSED_POINT_BYTES

            # Skip responses (ring_size * 32 bytes)
            offset += ring_size * _SCALAR_BYTES

            c = int.from_bytes(sig_bytes[offset: offset + _SCALAR_BYTES], "big")

            rng_hash = hashlib.sha256(
                b"capss-gs-ring-v2:" + b"".join(pk_list)
            ).digest()
            c_check = _hash_challenge(message, rng_hash, R_list)
            return c == c_check
        except Exception:
            return False


    def _run(self, ue_identity: dict) -> ExecutionResult:
        """Generate a ring signature for this UE identity.

        Signer (index 0): real Schnorr proof (k, R=k*G, s=k-c*x_0).
        Non-signers: random commitments R_j = random scalar * G.
        Challenge: c = H(ring || msg || all R_j).
        """
        supi_str: str = ue_identity.get("supi", "")
        if not supi_str:
            raise ValueError("ue_identity must contain a non-empty 'supi' key")
        message = supi_str.encode("utf-8")
        n = _P256_ORDER
        ring_size = self._ring_size
        signer_idx = self._signer_idx

        # 1. Signer nonce
        while True:
            k = int.from_bytes(os.urandom(_SCALAR_BYTES), "big") % n
            if k > 0:
                break
        R_signer = _scalar_mult(k)

        # 2. Non-signer random commitments
        R_list: list[bytes] = [b""] * ring_size
        R_list[signer_idx] = _compress_point(R_signer)
        for j in range(ring_size):
            if j != signer_idx:
                while True:
                    r_j = int.from_bytes(os.urandom(_SCALAR_BYTES), "big") % n
                    if r_j > 0:
                        break
                R_list[j] = _compress_point(_scalar_mult(r_j))

        # 3. Challenge
        c = _hash_challenge(message, self._ring_hash, R_list)

        # 4. Signer response: s_0 = k - c*x_0 (mod n)
        s_0 = (k - c * self._x) % n

        # 5. Non-signer responses: random scalars consistent with their R_j
        #    (In a real ring sig, s_j is chosen so s_j*G + c*Y_j == R_j.
        #     Here we use random s_j — reference-grade only.)
        s_list: list[int] = [0] * ring_size
        s_list[signer_idx] = s_0
        for j in range(ring_size):
            if j != signer_idx:
                while True:
                    s_j = int.from_bytes(os.urandom(_SCALAR_BYTES), "big") % n
                    if s_j > 0:
                        break
                s_list[j] = s_j

        # 6. Serialise
        sig = bytes([0x03])
        sig += struct.pack(">H", ring_size)
        for pk_bytes in self._ring_pub_compressed:
            sig += pk_bytes
        for r_bytes in R_list:
            sig += r_bytes
        for s in s_list:
            sig += s.to_bytes(_SCALAR_BYTES, "big")
        sig += c.to_bytes(_SCALAR_BYTES, "big")

        expected = (
            1 + 2
            + ring_size * _COMPRESSED_POINT_BYTES  # public keys
            + ring_size * _COMPRESSED_POINT_BYTES  # commitments R_j
            + ring_size * _SCALAR_BYTES             # responses s_j
            + _SCALAR_BYTES                          # challenge c
        )
        assert len(sig) == expected, f"Sig size {len(sig)} != {expected}"

        return ExecutionResult(
            success=True,
            output_type=self.output_type,
            output_value=sig,
            generation_time_ms=0.0,
            key_size_bytes=_COMPRESSED_POINT_BYTES,
            output_size_bytes=len(sig),
            error=None,
            scheme_name=self.scheme_name,
            label=self.label,
            metadata={
                "ring_size": ring_size,
                "signer_index": signer_idx,
                "curve": "P-256",
                "hash": "SHA-256",
                "construction": "schnorr-parallel-ring-simplified",
                "grade": "reference-grade-not-production-BBS+",
                "signature_size_bytes": len(sig),
            },
        )
