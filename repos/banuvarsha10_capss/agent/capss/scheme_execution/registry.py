"""capss/scheme_execution/registry.py

SchemeRegistry — maps scheme short_name → SchemeExecutor instance.

All 7 CAPSS scheme executors are registered here.  One instance of each
executor is created at registry construction time (or lazily, if using
the default singleton) and reused across calls.  This is safe because
all executor instances are stateless with respect to individual
execute() calls (any per-call state is local to _run()).

Usage:
    from capss.scheme_execution.registry import SchemeRegistry

    registry = SchemeRegistry()
    executor = registry.get("ECIES")
    result = executor.execute({"supi": "imsi-001010000000001"})

    # Or, using the module-level default singleton:
    from capss.scheme_execution.registry import default_registry
    result = default_registry.get("DP").execute({"supi": "..."})

Registered short names (exactly as in data/privacy_schemes.json):
    "ECIES"   → ECIESExecutor   (output: suci)
    "ML-KEM"  → MLKEMExecutor   (output: suci_proposed_pqc, real via liboqs)
    "DP"      → DPExecutor      (output: pseudonym)
    "AP"      → APExecutor      (output: padded_payload)
    "ZKP"     → ZKPExecutor     (output: zk_proof)
    "GS"      → GSExecutor      (output: group_signature)
    "IBE"     → IBEExecutor     (output: ibe_ciphertext)
"""

from __future__ import annotations

from typing import Dict

from capss.scheme_execution.base import SchemeExecutor
from capss.scheme_execution.executors.ecies_executor import ECIESExecutor
from capss.scheme_execution.executors.mlkem_executor import MLKEMExecutor
from capss.scheme_execution.executors.dp_executor import DPExecutor
from capss.scheme_execution.executors.ap_executor import APExecutor
from capss.scheme_execution.executors.zkp_executor import ZKPExecutor
from capss.scheme_execution.executors.gs_executor import GSExecutor
from capss.scheme_execution.executors.ibe_executor import IBEExecutor


class SchemeRegistry:
    """Registry mapping scheme short_name → SchemeExecutor instance.

    Each call to ``get()`` returns the same executor instance for a given
    name (executors are constructed once at registry init time).

    Raises:
        KeyError: if the requested scheme name is not registered, with a
            clear message listing available names.
    """

    def __init__(self) -> None:
        self._executors: Dict[str, SchemeExecutor] = {
            "ECIES": ECIESExecutor(),
            "ML-KEM": MLKEMExecutor(),
            "DP": DPExecutor(),
            "AP": APExecutor(),
            "ZKP": ZKPExecutor(),
            "GS": GSExecutor(),
            "IBE": IBEExecutor(),
        }

    def get(self, short_name: str) -> SchemeExecutor:
        """Return the executor for the given scheme short_name.

        Args:
            short_name: One of 'ECIES', 'ML-KEM', 'DP', 'AP', 'ZKP',
                'GS', 'IBE' (exact case, matching privacy_schemes.json).

        Returns:
            The registered SchemeExecutor instance.

        Raises:
            KeyError: if short_name is not registered.
        """
        if short_name not in self._executors:
            available = sorted(self._executors.keys())
            raise KeyError(
                f"Unknown scheme {short_name!r}. "
                f"Available schemes: {available}"
            )
        return self._executors[short_name]

    def available_schemes(self) -> list[str]:
        """Return a sorted list of all registered scheme short names."""
        return sorted(self._executors.keys())

    def execute(self, short_name: str, ue_identity: dict):
        """Convenience: get executor by name and execute immediately.

        Returns:
            ExecutionResult from the matching executor.
        """
        return self.get(short_name).execute(ue_identity)

    def __repr__(self) -> str:
        return f"SchemeRegistry(schemes={self.available_schemes()})"


# Module-level default singleton — constructed lazily on first use.
# Tests that need isolated executor state should create a new SchemeRegistry().
_default_registry: SchemeRegistry | None = None


def default_registry() -> SchemeRegistry:
    """Return the module-level default SchemeRegistry singleton.

    Constructed on first call; subsequent calls return the same instance.
    """
    global _default_registry
    if _default_registry is None:
        _default_registry = SchemeRegistry()
    return _default_registry
