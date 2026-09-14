"""dashboard_backend/identity_gen.py

Generates fresh, never-reused synthetic UE identities for the dashboard's
Normal Mode attack testing. Format matches demo_for_mentor.py exactly
(PLMN 999-70): "imsi-999700000000001" / "suci-0-999-70-0000-0-0-0000000001",
but with a randomized 10-digit MSIN body so repeated dashboard runs never
collide on the same identity. This is required for the cold-start/RAG
story: reusing fixed UEs would only ever show cold-start behavior once.

This is a NEW file. It does not import or modify anything under capss/,
systems/, privacy/, tests/, or data/ — it only produces plain strings in
the same format those modules already expect.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class UEIdentity:
    ue_id: str    # "imsi-999700000000123"
    suci: str     # "suci-0-999-70-0000-0-0-0000000123"
    msin: str     # "0000000123" (10 digits, the varying part)


def _random_msin(taken: set) -> str:
    while True:
        msin = str(random.randint(10_000_000, 9_999_999_999)).zfill(10)
        if msin not in taken:
            taken.add(msin)
            return msin


def generate_fresh_identities(count: int) -> List[UEIdentity]:
    """Generate `count` fresh, mutually-distinct UE identities."""
    taken: set = set()
    identities = []
    for _ in range(count):
        msin = _random_msin(taken)
        ue_id = f"imsi-99970{msin}"
        suci = f"suci-0-999-70-0000-0-0-{msin}"
        identities.append(UEIdentity(ue_id=ue_id, suci=suci, msin=msin))
    return identities


def mask_identity(ue_id: str) -> str:
    """Partially mask a UE identity for display (Part F: 'partially masked')."""
    if ue_id.startswith("imsi-") and len(ue_id) >= 9:
        digits = ue_id[len("imsi-"):]
        return f"imsi-{digits[:5]}{'*' * (len(digits) - 8)}{digits[-3:]}"
    return ue_id[:4] + "***" if len(ue_id) > 4 else "***"
