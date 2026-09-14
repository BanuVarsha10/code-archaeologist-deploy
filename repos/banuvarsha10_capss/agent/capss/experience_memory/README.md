# Experience Memory Module

The `ExperienceMemory` module stores and manages historical decisions and adaptations (`Experience` objects) for each UE.

## Classes
- `ExperienceMemory`: Manages storage and retrieval of experiences.

### Methods:
- `store(experience)`: Adds an experience and handles archiving if the limit is reached.
- `retrieve(ue_id)`: Gets all experiences for a UE.
- `get_latest(ue_id)`: Gets the most recent experience.
- `get_all_ues()`: Returns list of UEs.
- `get_stats()`: Returns summary stats.
- `archive_old(ue_id)`: Removes older experiences.
- `apply_decay(ue_id, factor)`: Applies time-decay to past experiences.
- `clear()`, `save()`, `load()`: Storage management.
- `get_adaptation_history(ue_id)`: Returns the history of scheme changes.

## Dependencies
- `json`, `os`, `datetime`
- `capss.schemas.experience.Experience`

## Example Usage
```python
from capss.experience_memory import ExperienceMemory

memory = ExperienceMemory("store.json")
latest = memory.get_latest("ue-001")
```
