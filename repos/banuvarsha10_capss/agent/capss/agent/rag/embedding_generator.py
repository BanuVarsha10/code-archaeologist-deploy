"""Embedding Generator for Cross-UE RAG Vector Retrieval.

Converts Experience or RequirementProfile objects into normalized feature vectors.
Deterministic, pure Python, zero external API calls or ML model latency.
"""

from typing import List, Optional
from capss.schemas.context import RequirementProfile, RegistrationContext
from capss.schemas.experience import Experience
from capss.agent.rag.experience_schema import profile_to_feature_vector, experience_to_feature_vector


class EmbeddingGenerator:
    """Generates normalized vector representations for profiles and stored experiences."""

    def embed_profile(
        self,
        profile: RequirementProfile,
        context: Optional[RegistrationContext] = None,
    ) -> List[float]:
        """Convert RequirementProfile (and optional RegistrationContext) into a feature vector."""
        return profile_to_feature_vector(profile, context)

    def embed_experience(self, experience: Experience) -> List[float]:
        """Convert a stored Experience object into a feature vector."""
        return experience_to_feature_vector(experience)
