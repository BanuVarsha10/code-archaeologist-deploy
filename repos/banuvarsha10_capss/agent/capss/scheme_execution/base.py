"""capss/scheme_execution/base.py

Abstract SchemeExecutor interface — all 7 executors must subclass this.

Design rules encoded here:
  1. execute() is the ONLY method subclasses must implement.
  2. Timing is measured via time.perf_counter() exclusively.
     The helper _timed_execute() wraps the subclass's _run() so that
     the measurement discipline is enforced at the base level, not
     left to individual executors (reducing the risk of one executor
     accidentally measuring differently).
  3. Failure mode: _run() may raise any exception; _timed_execute()
     catches it and returns a failed ExecutionResult rather than
     propagating a crash.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

from capss.scheme_execution.result import ExecutionResult


class SchemeExecutor(ABC):
    """Abstract base class for all CAPSS scheme executors.

    Subclass contract
    -----------------
    Implement ``_run(ue_identity)`` which performs the actual
    cryptographic work and returns an ``ExecutionResult`` with
    ``success=True``.  Do NOT catch exceptions in ``_run()`` — the
    base class handles that in ``execute()``.

    The ``execute()`` method measures wall-clock time *around* ``_run()``,
    ensures any exception is caught and converted to a failed result,
    and is the method callers should invoke.
    """

    @property
    @abstractmethod
    def scheme_name(self) -> str:
        """Short name of this scheme, e.g. 'ECIES'."""

    @property
    @abstractmethod
    def output_type(self) -> str:
        """The output_type string this executor always produces."""

    @property
    @abstractmethod
    def label(self) -> str:
        """Human-readable description of this executor's output."""

    @abstractmethod
    def _run(self, ue_identity: dict) -> ExecutionResult:
        """Core cryptographic work.  Must return a successful ExecutionResult.
        Do NOT time the work here — timing is handled by execute()."""

    def execute(self, ue_identity: dict) -> ExecutionResult:
        """Run the scheme and return an ExecutionResult.

        Timing is measured here with time.perf_counter() so ALL
        executors use exactly the same measurement approach.  Any
        exception from _run() is caught and returned as a failure.

        Args:
            ue_identity: Dict with at least a 'supi' key (the subscriber
                permanent identifier, e.g. 'imsi-001010000000001').
                Executors may require or use additional keys.

        Returns:
            ExecutionResult with generation_time_ms always populated.
        """
        t_start = time.perf_counter()
        try:
            result = self._run(ue_identity)
            # Overwrite generation_time_ms with the authoritative outer
            # measurement (prevents executors from reporting 0 or wrong values).
            elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            object.__setattr__(result, "generation_time_ms", elapsed_ms)
            return result
        except Exception as exc:  # noqa: BLE001
            elapsed_ms = (time.perf_counter() - t_start) * 1000.0
            return ExecutionResult(
                success=False,
                output_type=self.output_type,
                output_value=None,
                generation_time_ms=elapsed_ms,
                key_size_bytes=0,
                output_size_bytes=0,
                error=f"{type(exc).__name__}: {exc}",
                scheme_name=self.scheme_name,
                label=self.label,
            )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(scheme={self.scheme_name!r})"
