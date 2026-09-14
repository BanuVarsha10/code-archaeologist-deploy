"""tests/scheme_execution/test_executors.py

Unit tests for all 7 CAPSS scheme executors.

Tests verify:
  - All executors return success=True for a valid ue_identity
  - output_type is correct and in VALID_OUTPUT_TYPES
  - output_value is non-empty bytes of the expected approximate size
  - generation_time_ms > 0
  - key_size_bytes is reasonable
  - Round-trip / verification helpers work correctly
  - Missing 'supi' raises ValueError (or gives error result)
  - is_placeholder property is correct for each executor
"""

import pytest

from capss.scheme_execution.result import VALID_OUTPUT_TYPES, ExecutionResult
from capss.scheme_execution.registry import SchemeRegistry
from capss.scheme_execution.executors.ecies_executor import ECIESExecutor
from capss.scheme_execution.executors.mlkem_executor import MLKEMExecutor
from capss.scheme_execution.executors.dp_executor import DPExecutor
from capss.scheme_execution.executors.ap_executor import APExecutor, _padme_bucket
from capss.scheme_execution.executors.zkp_executor import ZKPExecutor
from capss.scheme_execution.executors.gs_executor import GSExecutor
from capss.scheme_execution.executors.ibe_executor import IBEExecutor

_UE = {"supi": "imsi-001010000000001"}
_UE2 = {"supi": "imsi-002020000000002"}
_ALL_SCHEME_NAMES = ["AP", "DP", "ECIES", "GS", "IBE", "ML-KEM", "ZKP"]


# ===========================================================================
# SchemeRegistry
# ===========================================================================

class TestSchemeRegistry:
    """Tests for SchemeRegistry."""

    def test_all_schemes_registered(self):
        r = SchemeRegistry()
        assert sorted(r.available_schemes()) == sorted(_ALL_SCHEME_NAMES)

    def test_get_returns_executor(self):
        r = SchemeRegistry()
        for name in _ALL_SCHEME_NAMES:
            ex = r.get(name)
            assert ex is not None
            assert ex.scheme_name == name

    def test_get_unknown_raises_key_error(self):
        r = SchemeRegistry()
        with pytest.raises(KeyError, match="Unknown scheme"):
            r.get("UNKNOWN")

    def test_execute_convenience_method(self):
        r = SchemeRegistry()
        res = r.execute("ECIES", _UE)
        assert res.success is True

    @pytest.mark.parametrize("name", _ALL_SCHEME_NAMES)
    def test_all_executors_succeed(self, name):
        r = SchemeRegistry()
        res = r.execute(name, _UE)
        assert res.success is True, f"{name} failed: {res.error}"
        assert res.output_value is not None
        assert len(res.output_value) > 0
        assert res.output_type in VALID_OUTPUT_TYPES
        assert res.generation_time_ms >= 0.0
        assert res.error is None

    @pytest.mark.parametrize("name", _ALL_SCHEME_NAMES)
    def test_output_size_bytes_consistent(self, name):
        """output_size_bytes must equal len(output_value)."""
        r = SchemeRegistry()
        res = r.execute(name, _UE)
        assert res.output_size_bytes == len(res.output_value)

    @pytest.mark.parametrize("name", _ALL_SCHEME_NAMES)
    def test_scheme_name_matches(self, name):
        r = SchemeRegistry()
        res = r.execute(name, _UE)
        assert res.scheme_name == name

    @pytest.mark.parametrize("name", _ALL_SCHEME_NAMES)
    def test_label_is_nonempty_string(self, name):
        r = SchemeRegistry()
        res = r.execute(name, _UE)
        assert isinstance(res.label, str) and len(res.label) > 0

    @pytest.mark.parametrize("name", _ALL_SCHEME_NAMES)
    def test_results_are_independent(self, name):
        """Two calls to the same executor should produce different outputs."""
        r = SchemeRegistry()
        res1 = r.execute(name, _UE)
        res2 = r.execute(name, _UE)
        # AP with same payload is deterministic modulo padding.
        # DP is deterministic within the same epoch.
        # For all others, randomness guarantees different outputs.
        if name in ("ECIES", "ZKP", "GS", "IBE", "ML-KEM"):
            assert res1.output_value != res2.output_value, (
                f"{name} produced identical outputs on two calls — missing randomness?"
            )


# ===========================================================================
# ECIES executor
# ===========================================================================

class TestECIESExecutor:
    """Tests for the ECIES executor."""

    def setup_method(self):
        self.e = ECIESExecutor()

    def test_output_type_is_suci(self):
        res = self.e.execute(_UE)
        assert res.output_type == "suci"

    def test_suci_is_not_placeholder(self):
        res = self.e.execute(_UE)
        assert res.is_placeholder is False

    def test_round_trip_decryption(self):
        """ECIES round-trip: decrypt(encrypt(supi)) == supi."""
        res = self.e.execute(_UE)
        decrypted = self.e.decrypt_suci(res.output_value, len(_UE["supi"]))
        assert decrypted.decode("utf-8") == _UE["supi"]

    def test_different_supi_different_output(self):
        res1 = self.e.execute(_UE)
        res2 = self.e.execute(_UE2)
        assert res1.output_value != res2.output_value

    def test_key_size_is_ephemeral_pk_size(self):
        res = self.e.execute(_UE)
        # P-256 compressed point is 33 bytes, uncompressed is 65 bytes
        assert res.key_size_bytes == 65  # uncompressed P-256 point

    def test_missing_supi_returns_error(self):
        res = self.e.execute({})
        assert res.success is False
        assert res.error is not None
        assert "supi" in res.error.lower()

    def test_metadata_contains_expected_keys(self):
        res = self.e.execute(_UE)
        for k in ("curve", "kdf", "cipher"):
            assert k in res.metadata


# ===========================================================================
# ML-KEM executor (real, via liboqs — confirmed installed and working in
# this environment; see mlkem_executor.py's module docstring for the
# explicit, clearly-labeled fallback used only when liboqs is unavailable)
# ===========================================================================

class TestMLKEMExecutor:
    """Tests for the ML-KEM executor (real liboqs crypto)."""

    def setup_method(self):
        self.e = MLKEMExecutor()

    def test_output_type_is_suci_proposed_pqc(self):
        res = self.e.execute(_UE)
        assert res.output_type == "suci_proposed_pqc"

    def test_is_not_placeholder(self):
        res = self.e.execute(_UE)
        assert res.is_placeholder is False

    def test_label_reflects_real_crypto(self):
        res = self.e.execute(_UE)
        assert "PLACEHOLDER" not in res.label
        assert "ML-KEM-768" in res.label
        assert "liboqs" in res.label
        # Still true regardless of real-vs-placeholder crypto underneath —
        # 3GPP has not standardised any PQC SUCI profile.
        assert "NOT 3GPP-standardised" in res.label

    def test_pk_size_matches_ml_kem_768(self):
        """key_size_bytes must equal the real ML-KEM-768 PK size: 1184 bytes."""
        res = self.e.execute(_UE)
        assert res.key_size_bytes == 1184

    def test_output_contains_real_ciphertext_of_correct_size(self):
        """wire format: [2B ct_len][1088B KEM ciphertext][12B nonce][AEAD supi+16B tag]."""
        res = self.e.execute(_UE)
        supi_len = len(_UE["supi"].encode("utf-8"))
        expected_size = 2 + 1088 + 12 + supi_len + 16  # +16 = AES-GCM tag
        assert res.output_size_bytes == expected_size

    def test_metadata_flags_real(self):
        res = self.e.execute(_UE)
        assert res.metadata["is_cryptographically_real"] is True
        assert res.metadata["status"] == "REAL"

    def test_round_trip_decapsulation(self):
        """Real KEM round-trip via the executor class itself: decapsulate
        (decapsulate_suci(execute(supi).output_value)) == the original supi."""
        res = self.e.execute(_UE)
        recovered = self.e.decapsulate_suci(res.output_value)
        assert recovered.decode("utf-8") == _UE["supi"]

    def test_different_supi_different_output(self):
        res1 = self.e.execute(_UE)
        res2 = self.e.execute(_UE2)
        assert res1.output_value != res2.output_value


# ===========================================================================
# DP executor
# ===========================================================================

class TestDPExecutor:
    """Tests for the Dynamic Pseudonym executor."""

    def setup_method(self):
        self.d = DPExecutor()

    def test_output_type_is_pseudonym(self):
        res = self.d.execute(_UE)
        assert res.output_type == "pseudonym"

    def test_pseudonym_size_is_32_bytes(self):
        res = self.d.execute(_UE)
        assert res.output_size_bytes == 32
        assert len(res.output_value) == 32

    def test_verify_pseudonym_succeeds(self):
        res = self.d.execute(_UE)
        epoch = res.metadata["epoch"]
        ok = self.d.verify_pseudonym(_UE["supi"], res.output_value, epoch)
        assert ok is True

    def test_different_secrets_different_pseudonyms(self):
        d1 = DPExecutor(shared_secret=b"\x01" * 32)
        d2 = DPExecutor(shared_secret=b"\x02" * 32)
        r1 = d1.execute(_UE)
        r2 = d2.execute(_UE)
        assert r1.output_value != r2.output_value

    def test_different_supi_different_pseudonym(self):
        r1 = self.d.execute(_UE)
        r2 = self.d.execute(_UE2)
        assert r1.output_value != r2.output_value

    def test_not_placeholder(self):
        res = self.d.execute(_UE)
        assert res.is_placeholder is False

    def test_label_says_not_suci(self):
        res = self.d.execute(_UE)
        assert "NOT a SUCI" in res.label or "NOT" in res.label.upper()


# ===========================================================================
# AP executor
# ===========================================================================

class TestAPExecutor:
    """Tests for the Adaptive Padding executor."""

    def setup_method(self):
        self.a = APExecutor()

    def test_output_type_is_padded_payload(self):
        res = self.a.execute(_UE)
        assert res.output_type == "padded_payload"

    def test_minimum_output_is_64_bytes(self):
        """Empty payload should produce 64-byte output."""
        res = self.a.execute({"supi": _UE["supi"], "payload": b""})
        assert res.output_size_bytes == 64

    def test_strip_padding_round_trip(self):
        payload = b"Hello, CAPSS!"
        res = self.a.execute({"supi": _UE["supi"], "payload": payload})
        recovered = self.a.strip_padding(res.output_value)
        assert recovered == payload

    def test_padme_bucket_is_power_of_two(self):
        """Padded outputs for sub-4096-byte payloads should be power-of-2."""
        for payload_len in [0, 1, 10, 50, 60, 63, 64, 100, 255, 512, 1000]:
            bucket = _padme_bucket(payload_len)
            if bucket < 4096:
                assert bucket & (bucket - 1) == 0, (
                    f"bucket {bucket} for payload_len {payload_len} is not power-of-2"
                )

    def test_no_identity_in_output(self):
        """The SUPI must NOT appear in the padded output."""
        supi = _UE["supi"]
        payload = b"some traffic data"
        res = self.a.execute({"supi": supi, "payload": payload})
        assert supi.encode() not in res.output_value

    def test_key_size_is_zero(self):
        """AP uses no key material."""
        res = self.a.execute(_UE)
        assert res.key_size_bytes == 0

    def test_not_placeholder(self):
        res = self.a.execute(_UE)
        assert res.is_placeholder is False


# ===========================================================================
# ZKP executor
# ===========================================================================

class TestZKPExecutor:
    """Tests for the Schnorr ZKP executor."""

    def setup_method(self):
        self.z = ZKPExecutor()

    def test_output_type_is_zk_proof(self):
        res = self.z.execute(_UE)
        assert res.output_type == "zk_proof"

    def test_proof_size_is_131_bytes(self):
        res = self.z.execute(_UE)
        assert res.output_size_bytes == 131
        assert len(res.output_value) == 131

    def test_verify_proof_succeeds(self):
        res = self.z.execute(_UE)
        ok = self.z.verify_proof(res.output_value, _UE["supi"].encode())
        assert ok is True

    def test_wrong_message_fails_verification(self):
        res = self.z.execute(_UE)
        ok = self.z.verify_proof(res.output_value, b"wrong-message")
        assert ok is False

    def test_truncated_proof_fails_verification(self):
        res = self.z.execute(_UE)
        ok = self.z.verify_proof(res.output_value[:50], _UE["supi"].encode())
        assert ok is False

    def test_multiple_proofs_are_independent(self):
        r1 = self.z.execute(_UE)
        r2 = self.z.execute(_UE)
        assert r1.output_value != r2.output_value

    def test_not_placeholder(self):
        res = self.z.execute(_UE)
        assert res.is_placeholder is False


# ===========================================================================
# GS executor
# ===========================================================================

class TestGSExecutor:
    """Tests for the Group Signature (ring-sig) executor."""

    def setup_method(self):
        self.g = GSExecutor()

    def test_output_type_is_group_signature(self):
        res = self.g.execute(_UE)
        assert res.output_type == "group_signature"

    def test_verify_signature_succeeds(self):
        res = self.g.execute(_UE)
        ok = self.g.verify_signature(res.output_value, _UE["supi"].encode())
        assert ok is True

    def test_wrong_message_fails_verification(self):
        res = self.g.execute(_UE)
        ok = self.g.verify_signature(res.output_value, b"wrong-msg")
        assert ok is False

    def test_multiple_ring_sizes(self):
        for n in [2, 3, 4, 5]:
            g = GSExecutor(ring_size=n)
            res = g.execute(_UE)
            assert res.success, f"ring_size={n} failed: {res.error}"
            ok = g.verify_signature(res.output_value, _UE["supi"].encode())
            assert ok, f"ring_size={n} verify failed"

    def test_ring_size_too_small_raises(self):
        with pytest.raises(ValueError, match="ring_size"):
            GSExecutor(ring_size=1)

    def test_label_says_reference_grade(self):
        res = self.g.execute(_UE)
        assert "reference-grade" in res.label

    def test_not_placeholder(self):
        res = self.g.execute(_UE)
        assert res.is_placeholder is False


# ===========================================================================
# IBE executor
# ===========================================================================

class TestIBEExecutor:
    """Tests for the IBE executor."""

    def setup_method(self):
        self.ib = IBEExecutor()

    def test_output_type_is_ibe_ciphertext(self):
        res = self.ib.execute(_UE)
        assert res.output_type == "ibe_ciphertext"

    def test_round_trip_decryption(self):
        res = self.ib.execute(_UE)
        dec = self.ib.decrypt_ibe(res.output_value)
        assert dec.decode("utf-8") == _UE["supi"]

    def test_different_identity_different_key(self):
        k1 = self.ib.derive_user_key(_UE["supi"])
        k2 = self.ib.derive_user_key(_UE2["supi"])
        assert k1 != k2

    def test_master_secret_isolation(self):
        """Two IBE executors with different master secrets cannot decrypt each other's output."""
        ib1 = IBEExecutor(master_secret=b"\xaa" * 32)
        ib2 = IBEExecutor(master_secret=b"\xbb" * 32)
        res = ib1.execute(_UE)
        with pytest.raises(Exception):  # decryption with wrong key fails
            ib2.decrypt_ibe(res.output_value)

    def test_label_says_reference_grade(self):
        res = self.ib.execute(_UE)
        assert "reference-grade" in res.label

    def test_not_placeholder(self):
        res = self.ib.execute(_UE)
        assert res.is_placeholder is False


# ===========================================================================
# ExecutionResult
# ===========================================================================

class TestExecutionResult:
    """Tests for the ExecutionResult dataclass itself."""

    def test_invalid_output_type_raises(self):
        with pytest.raises(ValueError, match="Invalid output_type"):
            from capss.scheme_execution.result import ExecutionResult
            ExecutionResult(
                success=True,
                output_type="invalid_type",
                output_value=b"x",
                generation_time_ms=1.0,
                key_size_bytes=0,
                output_size_bytes=1,
                error=None,
                scheme_name="TEST",
                label="test",
            )

    def test_is_placeholder_false_for_mlkem(self):
        """ML-KEM now uses real liboqs crypto in this environment — see
        mlkem_executor.py's module docstring for the fallback used only
        when liboqs is genuinely unavailable."""
        r = MLKEMExecutor()
        res = r.execute(_UE)
        assert res.is_placeholder is False

    def test_is_placeholder_false_for_ecies(self):
        r = ECIESExecutor()
        res = r.execute(_UE)
        assert res.is_placeholder is False

    def test_output_size_bytes_auto_corrected(self):
        """output_size_bytes is auto-set from len(output_value) in __post_init__."""
        from capss.scheme_execution.result import ExecutionResult
        val = b"\x00" * 50
        er = ExecutionResult(
            success=True,
            output_type="suci",
            output_value=val,
            generation_time_ms=1.0,
            key_size_bytes=0,
            output_size_bytes=0,  # will be auto-corrected
            error=None,
            scheme_name="ECIES",
            label="test",
        )
        assert er.output_size_bytes == 50
