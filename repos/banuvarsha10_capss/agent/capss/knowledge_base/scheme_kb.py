import json
import os
from typing import List, Optional, Tuple, Dict
from capss.schemas.scheme import PrivacyScheme
from capss.schemas.context import RequirementProfile

class SchemeKnowledgeBase:
    def __init__(self, schemes_path: str):
        self.schemes_path = schemes_path
        self.schemes: List[PrivacyScheme] = []
        self._load_schemes()

    def _load_schemes(self):
        if not os.path.exists(self.schemes_path):
            raise FileNotFoundError(f"Schemes file not found: {self.schemes_path}")
        
        with open(self.schemes_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, list):
                self.schemes = [PrivacyScheme(**s) for s in data]
            else:
                raise ValueError("Schemes file must contain a JSON array of scheme objects.")

    def get_scheme(self, scheme_id: str) -> Optional[PrivacyScheme]:
        for scheme in self.schemes:
            if scheme.id == scheme_id:
                return scheme
        return None

    def get_by_name(self, name: str) -> Optional[PrivacyScheme]:
        for scheme in self.schemes:
            if scheme.name.lower() == name.lower():
                return scheme
        return None

    def get_by_short_name(self, short_name: str) -> Optional[PrivacyScheme]:
        for scheme in self.schemes:
            if scheme.short_name == short_name:
                return scheme
        return None

    def get_all_schemes(self) -> List[PrivacyScheme]:
        return self.schemes

    def get_scheme_count(self) -> int:
        return len(self.schemes)

    def filter_by_capability(self, capability: str) -> List[PrivacyScheme]:
        return [s for s in self.schemes if capability in s.get_capabilities()]

    def filter_quantum_resistant(self) -> List[PrivacyScheme]:
        return [s for s in self.schemes if s.is_quantum_resistant()]

    def filter_by_context_preference(self, **kwargs) -> List[PrivacyScheme]:
        filtered = []
        for scheme in self.schemes:
            prefs = scheme.get_context_preferences()
            match = True
            for k, v in kwargs.items():
                if prefs.get(k) != v:
                    match = False
                    break
            if match:
                filtered.append(scheme)
        return filtered

    def get_compatible_hybrids(self, scheme_id: str) -> List[PrivacyScheme]:
        scheme = self.get_scheme(scheme_id)
        if not scheme:
            return []
        
        hybrids = scheme.get_compatible_hybrids()
        return [self.get_scheme(h) for h in hybrids if self.get_scheme(h) is not None]

    def get_knowledge_version(self) -> str:
        # Generate version based on highest scheme version or count
        return f"v1.0-schemes-{len(self.schemes)}"

    def get_knowledge_coverage(self, requirement_profile: RequirementProfile) -> Tuple[float, List[str]]:
        dimensions = ["threat_level", "privacy_requirement", "latency_requirement", "resource_profile"]
        covered = set()
        
        for scheme in self.schemes:
            # Assuming get_reasoning_profile indicates supported dimensions
            profile = scheme.get_reasoning_profile()
            if profile:
                for dim in dimensions:
                    if dim in profile:
                        covered.add(dim)
        
        missing = [d for d in dimensions if d not in covered]
        coverage_fraction = len(covered) / len(dimensions) if dimensions else 1.0
        return coverage_fraction, missing
