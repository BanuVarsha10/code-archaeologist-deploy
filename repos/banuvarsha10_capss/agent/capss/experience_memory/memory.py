import json
import os
from datetime import datetime
from typing import List, Optional, Dict
from capss.schemas.experience import Experience


class ExperienceMemory:
    def __init__(self, storage_path: str = 'experience_store.json', max_per_ue: int = 6):
        self.storage_path = storage_path
        self.max_per_ue = max_per_ue
        self.experiences: Dict[str, List[Experience]] = {}
        self.load()

    def store(self, experience: Experience) -> None:
        ue_id = experience.ue_id
        if ue_id not in self.experiences:
            self.experiences[ue_id] = []
        
        self.experiences[ue_id].append(experience)
        self.experiences[ue_id].sort(key=lambda x: x.timestamp, reverse=True)
        
        if len(self.experiences[ue_id]) > self.max_per_ue:
            self.archive_old(ue_id)
            
        self.save()

    def retrieve(self, ue_id: str) -> List[Experience]:
        return self.experiences.get(ue_id, [])

    def get_latest(self, ue_id: str) -> Optional[Experience]:
        exp = self.retrieve(ue_id)
        return exp[0] if exp else None

    def get_all_ues(self) -> List[str]:
        return list(self.experiences.keys())

    def get_stats(self) -> dict:
        total = sum(len(exps) for exps in self.experiences.values())
        ues = len(self.experiences)
        avg = total / ues if ues > 0 else 0
        return {
            "total_experiences": total,
            "total_ues": ues,
            "avg_per_ue": avg
        }

    def archive_old(self, ue_id: str) -> List[Experience]:
        if ue_id not in self.experiences:
            return []
        
        # Sort experiences by timestamp ascending (earliest/oldest first)
        sorted_by_time = sorted(self.experiences[ue_id], key=lambda x: x.timestamp)
        to_keep = sorted_by_time[-self.max_per_ue:]
        archived = sorted_by_time[:-self.max_per_ue]  # Evicted oldest experiences
        self.experiences[ue_id] = sorted(to_keep, key=lambda x: x.timestamp, reverse=True)
        return archived

    def apply_decay(self, ue_id: str, decay_factor: float = 0.95) -> None:
        if ue_id in self.experiences:
            for exp in self.experiences[ue_id]:
                exp.experience_decay_factor *= decay_factor
            self.save()

    def clear(self) -> None:
        self.experiences.clear()
        self.save()

    def save(self) -> None:
        data = {
            "version": "1.0",
            "last_updated": datetime.now().isoformat(),
            "experiences": {
                ue: [exp.model_dump(mode='json') for exp in exps]
                for ue, exps in self.experiences.items()
            }
        }
        with open(self.storage_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)

    def load(self) -> None:
        if not os.path.exists(self.storage_path):
            return
        
        if os.path.getsize(self.storage_path) == 0:
            self.experiences = {}
            return

        try:
            with open(self.storage_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.experiences = {
                    ue: [Experience(**exp) for exp in exps]
                    for ue, exps in data.get("experiences", {}).items()
                }
        except (json.JSONDecodeError, Exception):
            self.experiences = {}

    def get_adaptation_history(self, ue_id: str) -> List[dict]:
        history = []
        exps = sorted(self.retrieve(ue_id), key=lambda x: x.timestamp)
        for exp in exps:
            if exp.previous_scheme and exp.previous_scheme != exp.selected_scheme:
                history.append({
                    "timestamp": exp.timestamp,
                    "from": exp.previous_scheme,
                    "to": exp.selected_scheme,
                    "reason": exp.adaptation_reason
                })
        return history
