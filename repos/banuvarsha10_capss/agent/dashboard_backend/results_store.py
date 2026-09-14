"""dashboard_backend/results_store.py

Process-local, in-memory cache of dashboard run results. The existing
CAPSS code has no persisted, queryable "last decision trace" or "last
assessment" for a UE — assess_adaptation() and process_registration() only
return synchronously. This is purely new dashboard-facing state: it is
never written to disk and never touches experience_store.json or any other
existing storage.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional


class ResultsStore:
    def __init__(self) -> None:
        self._runs: Dict[str, Dict[str, Any]] = {}
        self._latest_by_ue: Dict[str, Dict[str, Any]] = {}

    def new_run_id(self) -> str:
        return uuid.uuid4().hex[:12]

    def save_run(self, run_id: str, devices: List[Dict[str, Any]], summary: Dict[str, Any]) -> None:
        self._runs[run_id] = {"run_id": run_id, "devices": devices, "summary": summary}
        for device in devices:
            self._latest_by_ue[device["ue_id"]] = device

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        return self._runs.get(run_id)

    def get_latest_for_ue(self, ue_id: str) -> Optional[Dict[str, Any]]:
        return self._latest_by_ue.get(ue_id)


# One shared, process-local instance for the whole FastAPI app.
store = ResultsStore()
