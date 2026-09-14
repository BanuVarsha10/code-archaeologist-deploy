"""capss/scheme_execution/executors/ibe_executor.py

Identity-Based Encryption (IBE) Executor — Simplified Identity-Keyed Hybrid.

Produces output_type="ibe_ciphertext" — NOT a SUCI.

LABEL: "Simplified IBE (identity-keyed hybrid, reference-grade,
        no BF pairing — documented substitute)"

===========================================================================
IMPLEMENTATION NOTE — REFERENCE-GRADE, DOCUMENTED SUBSTITUTE
===========================================================================
Full Boneh-Franklin IBE (the canonical construction) requires bilinear
pairings over a pairing-friendly elliptic curve (e.g. BN-256 or BLS12-381).
No pairing library (py_ecc, charm-crypto, mcl-python, etc.) is available
in this environment, so a fully standards-conformant BF-IBE cannot be built.

This executor implements IDENTITY-KEYED HYBRID ENCRYPTION as a documented
substitute.  It preserves IBE's defining property:

  "The receiver's decryption key is derived entirely from their identity
   string (e.g. SUPI) + a master secret.  No prior key exchange is needed.
   Any party with the master secret can generate the right decryption key
   on demand."

Construction:
  1. Setup: A master secret (32 bytes) is held by the Key Generation
     Authority (here: this executor instance).
  2. KeyDeriv: For identity id, derive user_key via HKDF-SHA-256:
       user_key = HKDF(master_secret, salt=id.encode('utf-8'),
                       info=b'capss-ibe-identity-key', length=16)
  3. Encrypt: AES-128-GCM(key=user_key, nonce=random(12), plaintext=SUPI)
  4. Ciphertext wire format:
       [2 bytes: identity_len] [identity] [12 bytes: nonce] [ciphertext+tag]

This simulates IBE semantics: the encrypted message can be decrypted
by anyone who derives user_key from the identity and master_secret,
without needing a pre-distributed per-user key.  The master secret is
the authority's privileged knowledge.

Explicitly labeled reference-grade everywhere output is surfaced.

Reference: Boneh, D., Franklin, M. (2001). Identity-based encryption from
the Weil pairing. CRYPTO 2001. Springer, LNCS 2139.
"""

from __future__ import annotations

import os
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from capss.scheme_execution.base import SchemeExecutor
from capss.scheme_execution.result import ExecutionResult

_GCM_NONCE_BYTES: int = 12
_AES_KEY_BYTES: int = 16
_MASTER_SECRET_BYTES: int = 32


class IBEExecutor(SchemeExecutor):
    """Identity-Based Encryption executor — identity-keyed hybrid (AES-GCM).

    REFERENCE-GRADE — Documented substitute for Boneh-Franklin IBE.
    See module docstring for explanation.

    Args:
        master_secret: 32-byte master secret held by the KGA (Key Generation
            Authority).  If not provided, a stable random secret is
            generated at construction time.
    """

    def __init__(self, master_secret: bytes | None = None) -> None:
        import secrets as _secrets
        self._master_secret: bytes = (
            master_secret
            if master_secret is not None
            else _secrets.token_bytes(_MASTER_SECRET_BYTES)
        )

    @property
    def scheme_name(self) -> str:
        return "IBE"

    @property
    def output_type(self) -> str:
        return "ibe_ciphertext"

    @property
    def label(self) -> str:
        return (
            "Simplified IBE (identity-keyed hybrid, reference-grade, "
            "no BF pairing — documented substitute). NOT a SUCI. "
            "Derives user_key = HKDF(master_secret, salt=identity), "
            "then encrypts with AES-128-GCM. Preserves IBE's core "
            "property: decryption key is derived on demand from identity."
        )

    # ------------------------------------------------------------------
    # Public helper: derive user key + decrypt (for tests)
    # ------------------------------------------------------------------

    def derive_user_key(self, identity: str) -> bytes:
        """Derive the AES key for a given identity (simulates IBE Extract)."""
        backend = default_backend()
        hkdf = HKDF(
            algorithm=SHA256(),
            length=_AES_KEY_BYTES,
            salt=identity.encode("utf-8"),
            info=b"capss-ibe-identity-key",
            backend=backend,
        )
        return hkdf.derive(self._master_secret)

    def decrypt_ibe(self, ciphertext_blob: bytes) -> bytes:
        """Decrypt an IBE ciphertext produced by this executor."""
        offset = 0
        (id_len,) = struct.unpack_from(">H", ciphertext_blob, offset)
        offset += 2
        identity = ciphertext_blob[offset: offset + id_len].decode("utf-8")
        offset += id_len
        nonce = ciphertext_blob[offset: offset + _GCM_NONCE_BYTES]
        offset += _GCM_NONCE_BYTES
        ct_with_tag = ciphertext_blob[offset:]

        user_key = self.derive_user_key(identity)
        aesgcm = AESGCM(user_key)
        return aesgcm.decrypt(nonce, ct_with_tag, None)

    # ------------------------------------------------------------------
    # Core crypto
    # ------------------------------------------------------------------

    def _run(self, ue_identity: dict) -> ExecutionResult:
        """Encrypt SUPI using identity-derived AES-128-GCM key."""
        supi_str: str = ue_identity.get("supi", "")
        if not supi_str:
            raise ValueError("ue_identity must contain a non-empty 'supi' key")

        # The identity is the supi (this is the IBE semantics: key is
        # derived from the recipient's identity string)
        identity = supi_str

        # Step 1: Derive user key from identity
        user_key = self.derive_user_key(identity)

        # Step 2: Encrypt with AES-128-GCM
        nonce = os.urandom(_GCM_NONCE_BYTES)
        aesgcm = AESGCM(user_key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, supi_str.encode("utf-8"), None)

        # Step 3: Wire format: [2-byte id_len] [identity] [nonce] [ct+tag]
        id_bytes = identity.encode("utf-8")
        blob = (
            struct.pack(">H", len(id_bytes))
            + id_bytes
            + nonce
            + ciphertext_with_tag
        )

        return ExecutionResult(
            success=True,
            output_type=self.output_type,
            output_value=blob,
            generation_time_ms=0.0,  # overwritten by base execute()
            key_size_bytes=_MASTER_SECRET_BYTES,
            output_size_bytes=len(blob),
            error=None,
            scheme_name=self.scheme_name,
            label=self.label,
            metadata={
                "construction": "identity-keyed-hybrid-AES-GCM",
                "kdf": "HKDF-SHA-256",
                "cipher": "AES-128-GCM",
                "grade": "reference-grade-documented-substitute-no-BF-pairing",
                "identity_used": identity,
                "nonce_size": _GCM_NONCE_BYTES,
            },
        )
