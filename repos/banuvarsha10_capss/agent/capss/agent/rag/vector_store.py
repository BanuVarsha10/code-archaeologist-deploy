"""In-Memory Vector Store with Cosine Similarity for CAPSS RAG Experience Retrieval."""

import json
import os
from typing import List, Tuple, Dict, Any, Optional
import numpy as np


class VectorStore:
    """In-memory vector store supporting cosine similarity queries and metadata filtering."""

    def __init__(self) -> None:
        self.ids: List[str] = []
        self.vectors: List[List[float]] = []
        self.metadata: List[Dict[str, Any]] = []

    def add(self, experience_id: str, vector: List[float], metadata: Dict[str, Any]) -> None:
        """Add or update an experience vector and metadata."""
        if experience_id in self.ids:
            idx = self.ids.index(experience_id)
            self.vectors[idx] = vector
            self.metadata[idx] = metadata
        else:
            self.ids.append(experience_id)
            self.vectors.append(vector)
            self.metadata.append(metadata)

    def query(
        self,
        vector: List[float],
        top_k: int = 5,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Tuple[str, float]]:
        """
        Query top_k most similar experience IDs using cosine similarity.
        Optionally filter by metadata (e.g. exclude_ue_id).
        Returns list of (experience_id, similarity_score) tuples.
        """
        if not self.ids or not self.vectors:
            return []

        query_vec = np.array(vector, dtype=np.float32)
        query_norm = np.linalg.norm(query_vec)
        if query_norm == 0:
            return []

        matrix = np.array(self.vectors, dtype=np.float32)
        norms = np.linalg.norm(matrix, axis=1)
        norms[norms == 0] = 1.0

        # Cosine similarity calculation: (matrix @ query) / (norms * query_norm)
        sims = (matrix @ query_vec) / (norms * query_norm)

        results = []
        exclude_ue = filters.get("exclude_ue_id") if filters else None

        for idx, (exp_id, score) in enumerate(zip(self.ids, sims)):
            meta = self.metadata[idx]
            if exclude_ue and meta.get("ue_id") == exclude_ue:
                continue
            results.append((exp_id, float(score)))

        # Sort descending by similarity score
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]

    def delete(self, experience_id: str) -> None:
        """Remove an experience by ID."""
        if experience_id in self.ids:
            idx = self.ids.index(experience_id)
            self.ids.pop(idx)
            self.vectors.pop(idx)
            self.metadata.pop(idx)

    def persist(self, path: str) -> None:
        """Persist vector store state to a JSON file."""
        data = {
            "version": "1.0",
            "ids": self.ids,
            "vectors": self.vectors,
            "metadata": self.metadata,
        }
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def load(self, path: str) -> None:
        """Load vector store state from a JSON file."""
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.ids = data.get("ids", [])
        self.vectors = data.get("vectors", [])
        self.metadata = data.get("metadata", [])
