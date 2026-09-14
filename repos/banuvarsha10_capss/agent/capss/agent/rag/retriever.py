"""Cross-UE Experience Retriever for CAPSS RAG Subsystem."""

from typing import List, Tuple, Optional, Dict
from capss.schemas.context import RequirementProfile, RegistrationContext
from capss.schemas.experience import Experience
from capss.agent.rag.vector_store import VectorStore
from capss.agent.rag.embedding_generator import EmbeddingGenerator


class ExperienceRetriever:
    """Retrieves similar past experiences across ALL UEs based on vector similarity."""

    def __init__(
        self,
        vector_store: Optional[VectorStore] = None,
        embedding_generator: Optional[EmbeddingGenerator] = None,
    ) -> None:
        self.vector_store = vector_store or VectorStore()
        self.embedding_generator = embedding_generator or EmbeddingGenerator()
        self._experience_map: Dict[str, Experience] = {}

    def index_experience(self, experience: Experience) -> None:
        """Indexes an experience into the vector store for cross-UE retrieval."""
        exp_id = getattr(experience, "experience_id", None) or str(id(experience))
        ue_id = getattr(experience, "ue_id", None)
        vec = self.embedding_generator.embed_experience(experience)

        self._experience_map[exp_id] = experience
        self.vector_store.add(
            experience_id=exp_id,
            vector=vec,
            metadata={"ue_id": ue_id, "selected_scheme": getattr(experience, "selected_scheme", None)},
        )

    def retrieve_similar(
        self,
        requirement_profile: RequirementProfile,
        context: Optional[RegistrationContext] = None,
        top_k: int = 5,
        exclude_ue_id: Optional[str] = None,
    ) -> List[Tuple[Experience, float]]:
        """
        Retrieves top_k similar past experiences across UEs matching requirement_profile.
        Returns list of (Experience, similarity_score) tuples.
        """
        query_vec = self.embedding_generator.embed_profile(requirement_profile, context)
        filters = {"exclude_ue_id": exclude_ue_id} if exclude_ue_id else None

        matches = self.vector_store.query(query_vec, top_k=top_k, filters=filters)

        results = []
        for exp_id, sim in matches:
            if exp_id in self._experience_map:
                results.append((self._experience_map[exp_id], sim))
        return results

    def clear(self) -> None:
        """Clear all indexed experiences."""
        self._experience_map.clear()
        self.vector_store = VectorStore()
