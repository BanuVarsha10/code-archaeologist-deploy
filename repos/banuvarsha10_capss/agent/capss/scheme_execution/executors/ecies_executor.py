"""capss/scheme_execution/executors/ecies_executor.py

ECIES Executor — produces real 3GPP-style SUCI.

This is the ONLY executor that produces a true "suci" output type.

Cryptographic construction (per 3GPP TS 33.501, Annex C.4):
  1. Generate a fresh ephemeral EC keypair on NIST P-256.
  2. Perform ECDH between the ephemeral private key and the HN public key
     to derive a shared secret.
  3. Derive encryption key and MAC key via HKDF-SHA-256.
  4. Encrypt the SUPI (subscriber permanent identifier) with AES-128-GCM.
  5. Assemble SUCI: scheme_output = ephemeral_pk || ciphertext || tag.

In a live deployment the HN public key would come from the network's
configuration.  Here we use a stable, deterministic per-executor key
generated once at construction time, so that:
  - Tests can verify round-trip decryption.
  - Multiple calls are independent (fresh ephemeral key each time).

Dependency: `cryptography` >= 3.0 (already in requirements.txt).
"""

from __future__ import annotations

import os
import struct

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    SECP256R1,
    generate_private_key,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from capss.scheme_execution.base import SchemeExecutor
from capss.scheme_execution.result import ExecutionResult

# AES-GCM nonce size (96 bits per NIST SP 800-38D recommendation)
_GCM_NONCE_BYTES = 12
# AES-128 key size
_AES_KEY_BYTES = 16
# HKDF output: 16 bytes encryption key + 16 bytes unused (MAC is handled by GCM)
_HKDF_OUTPUT_BYTES = 32


class ECIESExecutor(SchemeExecutor):
    """ECIES-based SUCI generator (3GPP TS 33.501, Annex C.4).

    Produces output_type="suci" — the ONLY standardised SUCI in CAPSS.

    Wire format (schema_output bytes):
      [2 bytes: ephemeral_pk_len] [ephemeral_pk] [12 bytes: nonce]
      [ciphertext] [16 bytes: GCM tag]

    The ephemeral public key is serialized as uncompressed SEC 1 point
    (65 bytes for P-256): 0x04 || x || y.
    """

    def __init__(self) -> None:
        backend = default_backend()
        # Home Network (HN) key pair — stable across the lifetime of
        # this executor instance.  In production this would be loaded
        # from operator config.
        self._hn_private_key = generate_private_key(SECP256R1(), backend)
        self._hn_public_key = self._hn_private_key.public_key()

    @property
    def scheme_name(self) -> str:
        return "ECIES"

    @property
    def output_type(self) -> str:
        return "suci"

    @property
    def label(self) -> str:
        return (
            "SUCI (3GPP TS 33.501, Annex C.4) — "
            "ECDH P-256 + HKDF-SHA-256 + AES-128-GCM"
        )

    # ------------------------------------------------------------------
    # Public helper: decrypt (for round-trip tests)
    # ------------------------------------------------------------------

    def decrypt_suci(self, suci_bytes: bytes, supi_len: int) -> bytes:
        """Decrypt a SUCI produced by this executor, returning the SUPI bytes.

        Only usable within the same executor instance (requires _hn_private_key).
        """
        backend = default_backend()
        offset = 0

        # Parse ephemeral PK length
        (eph_pk_len,) = struct.unpack_from(">H", suci_bytes, offset)
        offset += 2

        # Parse ephemeral PK
        eph_pk_bytes = suci_bytes[offset: offset + eph_pk_len]
        offset += eph_pk_len

        # Parse nonce
        nonce = suci_bytes[offset: offset + _GCM_NONCE_BYTES]
        offset += _GCM_NONCE_BYTES

        # Remaining: ciphertext || tag (GCM tag is last 16 bytes)
        ct_with_tag = suci_bytes[offset:]

        # Reconstruct ephemeral public key
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from cryptography.hazmat.primitives.asymmetric.ec import (
            EllipticCurvePublicKey,
            EllipticCurvePublicNumbers,
        )
        from cryptography.hazmat.primitives.asymmetric import ec
        eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(SECP256R1(), eph_pk_bytes)

        # ECDH
        shared_secret = self._hn_private_key.exchange(ECDH(), eph_pub)

        # HKDF
        hkdf = HKDF(
            algorithm=SHA256(),
            length=_HKDF_OUTPUT_BYTES,
            salt=None,
            info=b"capss-ecies-suci",
            backend=backend,
        )
        key_material = hkdf.derive(shared_secret)
        enc_key = key_material[:_AES_KEY_BYTES]

        # AES-128-GCM decrypt
        aesgcm = AESGCM(enc_key)
        plaintext = aesgcm.decrypt(nonce, ct_with_tag, None)
        return plaintext

    # ------------------------------------------------------------------
    # Core crypto work
    # ------------------------------------------------------------------

    def _run(self, ue_identity: dict) -> ExecutionResult:
        """Encrypt SUPI into a SUCI using ECIES (P-256 / HKDF / AES-GCM)."""
        supi_str: str = ue_identity.get("supi", "")
        if not supi_str:
            raise ValueError("ue_identity must contain a non-empty 'supi' key")

        supi_bytes = supi_str.encode("utf-8")
        backend = default_backend()

        # Step 1: Fresh ephemeral keypair
        eph_priv = generate_private_key(SECP256R1(), backend)
        eph_pub = eph_priv.public_key()

        # Serialize ephemeral public key (uncompressed, 65 bytes for P-256)
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )
        eph_pk_bytes = eph_pub.public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )

        # Step 2: ECDH shared secret
        shared_secret = eph_priv.exchange(ECDH(), self._hn_public_key)

        # Step 3: HKDF key derivation
        hkdf = HKDF(
            algorithm=SHA256(),
            length=_HKDF_OUTPUT_BYTES,
            salt=None,
            info=b"capss-ecies-suci",
            backend=backend,
        )
        key_material = hkdf.derive(shared_secret)
        enc_key = key_material[:_AES_KEY_BYTES]

        # Step 4: AES-128-GCM encryption
        nonce = os.urandom(_GCM_NONCE_BYTES)
        aesgcm = AESGCM(enc_key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, supi_bytes, None)

        # Step 5: Assemble SUCI wire bytes
        # Format: [2-byte eph_pk_len] [eph_pk] [nonce] [ciphertext+tag]
        suci_bytes = (
            struct.pack(">H", len(eph_pk_bytes))
            + eph_pk_bytes
            + nonce
            + ciphertext_with_tag
        )

        return ExecutionResult(
            success=True,
            output_type=self.output_type,
            output_value=suci_bytes,
            generation_time_ms=0.0,  # overwritten by base execute()
            key_size_bytes=len(eph_pk_bytes),
            output_size_bytes=len(suci_bytes),
            error=None,
            scheme_name=self.scheme_name,
            label=self.label,
            metadata={
                "curve": "P-256",
                "kdf": "HKDF-SHA-256",
                "cipher": "AES-128-GCM",
                "ephemeral_pk_size": len(eph_pk_bytes),
                "nonce_size": _GCM_NONCE_BYTES,
                "supi_len": len(supi_bytes),
            },
        )
