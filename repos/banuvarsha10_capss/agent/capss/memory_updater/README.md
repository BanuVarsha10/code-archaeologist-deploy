# Memory Updater Module

The `MemoryUpdater` bridges the output of a recommendation/policy application into the `ExperienceMemory`. It encapsulates the creation and tracking of adaptation history.

## Classes
- `MemoryUpdater`: Generates `Experience` objects and stores them in `ExperienceMemory`.

### Methods:
- `update(policy, context, recommendation)`: Calculates changes from past experiences and creates a new `Experience`.
- `_compute_adaptation_info(ue_id, new_scheme)`: Determines if a change occurred compared to the last experience.
- `_update_confidence_trend(ue_id, new_confidence)`: Updates the sliding window trend of confidence.
- `_compute_average_decision_score(ue_id, new_score)`: Calculates the running average of decision confidence.

## Dependencies
- `uuid`, `datetime`
- `capss.experience_memory.ExperienceMemory`
- `capss.schemas.*`

## Example Usage
```python
from capss.memory_updater import MemoryUpdater

updater = MemoryUpdater(experience_memory)
exp = updater.update(policy, context, recommendation)
```
