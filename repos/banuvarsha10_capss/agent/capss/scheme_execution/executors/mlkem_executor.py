"""capss/scheme_execution/executors/mlkem_executor.py

ML-KEM (Module Lattice Key Encapsulation Mechanism) Executor.

Produces output_type="suci_proposed_pqc" — a SUCI-shaped output for a
proposed post-quantum SUCI profile.  This is NOT a 3GPP-standardised SUCI
— 3GPP has not standardised any KEM-based post-quantum SUCI concealment
profile, so "proposed" is accurate regardless of what's underneath it.

===========================================================================
LIBRARY STATUS — REAL ML-KEM-768, VIA liboqs-python
===========================================================================

Confirmed directly in this environment: `import oqs` succeeds, a real
ML-KEM-768 KeyGen/Encaps/Decaps round-trip produces matching shared
secrets, and both the public key (1184 bytes) and ciphertext (1088 bytes)
match the real FIPS 203 ML-KEM-768 sizes. This executor now performs real
lattice-based key encapsulation via liboqs — no hash-based simulation.

Construction (KEM-then-DEM, mirroring ECIESExecutor's real ECDH-then-AEAD
design so the two "conceal a SUPI" executors follow the same pattern):
  1. A stable "home network" ML-KEM-768 keypair is generated once, at
     executor construction time (mirrors ECIESExecutor's stable HN EC
     keypair) — not regenerated per call.
  2. Each call runs a FRESH Encaps(hn_public_key), producing a genuinely
     new (ciphertext, shared_secret) pair — this is ML-KEM's own built-in
     per-encapsulation randomness, the KEM analogue of ECIES's fresh
     ephemeral EC keypair per call.
  3. The shared_secret is passed through the SAME HKDF-SHA-256 construction
     ECIESExecutor uses to derive a uniform AES-128 key (a raw KEM shared
     secret, like a raw ECDH secret, isn't safe to use as a cipher key
     directly).
  4. AES-128-GCM encrypts the real SUPI bytes — authenticated encryption,
     so a tampered SUCI is detected, not just kept confidential.
  5. Wire format: [2B ct_len][KEM ciphertext][12B nonce][AEAD ciphertext+tag]
     — the same shape as ECIES's [2B pk_len][ephemeral pk][nonce][AEAD ct],
     with the KEM ciphertext standing in for the ephemeral EC public key.

FALLBACK — kept, not removed, and never silent: SchemeRegistry constructs
all 7 executors eagerly at startup (registry.py), so a hard ImportError
here would take down every OTHER real scheme too if this code ever runs
somewhere liboqs isn't installed — too broad a blast radius for one
scheme's dependency. If `import oqs` fails, this module falls back to the
same timing/size-representative hash-based construction the old
placeholder used, but every ExecutionResult it produces is unambiguously
labeled and flagged as such (label starts with "PLACEHOLDER", metadata
carries status="PLACEHOLDER" and is_cryptographically_real=False) — never
silently indistinguishable from a real result.

ML-KEM-768 Reference Sizes (from FIPS 203):
  ek (encapsulation/public key): 1184 bytes
  dk (decapsulation/private key): 2400 bytes
  c  (ciphertext):               1088 bytes
  K  (shared secret):              32 bytes
"""

from __future__ import annotations

import hashlib
import os
import struct
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from capss.scheme_execution.base import SchemeExecutor
from capss.scheme_execution.result import ExecutionResult

try:
    import oqs as _oqs
    _OQS_IMPORT_ERROR: Optional[Exception] = None
except Exception as _exc:  # noqa: BLE001 — genuinely any import-time failure
    # (missing shared library, failed on-demand native build, ...) must
    # route through the explicit, labeled fallback below, not crash the
    # whole SchemeRegistry.
    _oqs = None
    _OQS_IMPORT_ERROR = _exc

_ML_KEM_ALG = "ML-KEM-768"

# ML-KEM-768 correct sizes per FIPS 203
_ML_KEM_768_PK_BYTES: int = 1184   # encapsulation key (public)
_ML_KEM_768_CT_BYTES: int = 1088   # ciphertext
_ML_KEM_768_SS_BYTES: int = 32     # shared secret

_GCM_NONCE_BYTES = 12
_AES_KEY_BYTES = 16
_HKDF_OUTPUT_BYTES = 32

_REAL_LABEL: str = (
    "ML-KEM-768 (FIPS 203, via liboqs) — real post-quantum key "
    "encapsulation + HKDF-SHA-256 + AES-128-GCM. Proposed post-quantum "
    "SUCI profile — NOT 3GPP-standardised."
)

_PLACEHOLDER_LABEL: str = (
    "PLACEHOLDER — timing/size representative only, NOT cryptographically "
    "real ML-KEM. liboqs is unavailable in this environment "
    f"({_OQS_IMPORT_ERROR!r} at import time). "
    "Output sizes match real ML-KEM-768 (FIPS 203): "
    f"ciphertext {_ML_KEM_768_CT_BYTES} bytes, public key {_ML_KEM_768_PK_BYTES} bytes. "
    "Proposed post-quantum SUCI profile — NOT 3GPP-standardised."
)


class MLKEMExecutor(SchemeExecutor):
    """ML-KEM-768 SUCI-shaped executor — real liboqs crypto when available,
    an explicit, clearly-labeled timing/size-representative fallback
    otherwise (see module docstring for why the fallback is kept rather
    than a hard ImportError).
    """

    def __init__(self) -> None:
        self._real = _oqs is not None
        if self._real:
            # Stable HN keypair, generated once — mirrors ECIESExecutor's
            # stable HN EC keypair. Kept alive for the executor's lifetime
            # so decapsulate_suci() (round-trip testing) can use the same
            # instance's retained secret key.
            self._hn_kem = _oqs.KeyEncapsulation(_ML_KEM_ALG)
            self._hn_public_key = self._hn_kem.generate_keypair()

    @property
    def scheme_name(self) -> str:
        return "ML-KEM"

    @property
    def output_type(self) -> str:
        return "suci_proposed_pqc"

    @property
    def label(self) -> str:
        return _REAL_LABEL if self._real else _PLACEHOLDER_LABEL

    # ------------------------------------------------------------------
    # Public helper: decapsulate + decrypt (for round-trip tests) — only
    # meaningful when real crypto is in use.
    # ------------------------------------------------------------------

    def decapsulate_suci(self, wrapped: bytes) -> bytes:
        """Decrypts a SUCI produced by this executor's real path, returning
        the SUPI bytes. Only usable when self._real (requires the HN secret
        key retained on self._hn_kem)."""
        if not self._real:
            raise RuntimeError(
                "decapsulate_suci() requires real liboqs crypto — this "
                "executor is running the placeholder fallback (see .label)."
            )
        offset = 0
        (ct_len,) = struct.unpack_from(">H", wrapped, offset)
        offset += 2
        ciphertext = wrapped[offset:offset + ct_len]
        offset += ct_len
        nonce = wrapped[offset:offset + _GCM_NONCE_BYTES]
        offset += _GCM_NONCE_BYTES
        ct_with_tag = wrapped[offset:]

        shared_secret = self._hn_kem.decap_secret(ciphertext)
        enc_key = self._derive_key(shared_secret)
        aesgcm = AESGCM(enc_key)
        return aesgcm.decrypt(nonce, ct_with_tag, None)

    @staticmethod
    def _derive_key(shared_secret: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=SHA256(),
            length=_HKDF_OUTPUT_BYTES,
            salt=None,
            info=b"capss-mlkem-suci",
            backend=default_backend(),
        )
        return hkdf.derive(shared_secret)[:_AES_KEY_BYTES]

    # ------------------------------------------------------------------
    # Core work
    # ------------------------------------------------------------------

    def _run(self, ue_identity: dict) -> ExecutionResult:
        supi_str: str = ue_identity.get("supi", "")
        if not supi_str:
            raise ValueError("ue_identity must contain a non-empty 'supi' key")
        supi_bytes = supi_str.encode("utf-8")

        if self._real:
            return self._run_real(supi_bytes)
        return self._run_placeholder(supi_bytes)

    def _run_real(self, supi_bytes: bytes) -> ExecutionResult:
        # Fresh Encaps() per call — a NEW KeyEncapsulation instance, since
        # the sender (UE) side never needs to generate its own keypair,
        # only knows the HN's public key. This mirrors ECIES's fresh
        # ephemeral keypair per call.
        ue_kem = _oqs.KeyEncapsulation(_ML_KEM_ALG)
        try:
            ciphertext, shared_secret = ue_kem.encap_secret(self._hn_public_key)
        finally:
            ue_kem.free()

        enc_key = self._derive_key(shared_secret)
        nonce = os.urandom(_GCM_NONCE_BYTES)
        aesgcm = AESGCM(enc_key)
        ct_with_tag = aesgcm.encrypt(nonce, supi_bytes, None)

        wrapped = (
            struct.pack(">H", len(ciphertext))
            + ciphertext
            + nonce
            + ct_with_tag
        )

        return ExecutionResult(
            success=True,
            output_type=self.output_type,
            output_value=wrapped,
            generation_time_ms=0.0,  # overwritten by base execute()
            key_size_bytes=len(self._hn_public_key),
            output_size_bytes=len(wrapped),
            error=None,
            scheme_name=self.scheme_name,
            label=self.label,
            metadata={
                "status": "REAL",
                "algorithm": f"{_ML_KEM_ALG} (FIPS 203, via liboqs)",
                "kem_public_key_bytes": len(self._hn_public_key),
                "kem_ciphertext_bytes": len(ciphertext),
                "kem_shared_secret_bytes": len(shared_secret),
                "kdf": "HKDF-SHA-256",
                "cipher": "AES-128-GCM",
                "is_cryptographically_real": True,
            },
        )

    def _run_placeholder(self, supi_bytes: bytes) -> ExecutionResult:
        """Timing/size-representative fallback — identical logic to the
        original placeholder, used ONLY when liboqs is unavailable. See
        module docstring for why this is kept as an explicit, clearly
        labeled path rather than removed."""
        import secrets as _secrets
        seed = _secrets.token_bytes(32)

        shake_keygen = hashlib.shake_256(seed + b"\x00keygen")
        simulated_pk = shake_keygen.digest(_ML_KEM_768_PK_BYTES)

        shake_encaps = hashlib.shake_256(seed + b"\x01encaps" + supi_bytes)
        simulated_ct = shake_encaps.digest(_ML_KEM_768_CT_BYTES)

        wrapped = (
            struct.pack(">H", _ML_KEM_768_PK_BYTES)
            + simulated_pk
            + struct.pack(">H", _ML_KEM_768_CT_BYTES)
            + simulated_ct
        )

        return ExecutionResult(
            success=True,
            output_type=self.output_type,
            output_value=wrapped,
            generation_time_ms=0.0,  # overwritten by base execute()
            key_size_bytes=_ML_KEM_768_PK_BYTES,
            output_size_bytes=len(wrapped),
            error=None,
            scheme_name=self.scheme_name,
            label=self.label,
            metadata={
                "status": "PLACEHOLDER",
                "reason": f"liboqs unavailable at import time: {_OQS_IMPORT_ERROR!r}",
                "algorithm": "ML-KEM-768 (FIPS 203)",
                "simulated_pk_bytes": _ML_KEM_768_PK_BYTES,
                "simulated_ct_bytes": _ML_KEM_768_CT_BYTES,
                "hash_ops_used": ["SHAKE-256"],
                "is_cryptographically_real": False,
            },
        )
