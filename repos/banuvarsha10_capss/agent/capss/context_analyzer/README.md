# Context Analyzer Module

The `ContextAnalyzer` converts raw `RegistrationContext` data into a structured `RequirementProfile` which defines the security and privacy needs for the current context.

## Classes
- `ContextAnalyzer`: Generates RequirementProfiles.

### Methods:
- `analyze(context, experiences)`: Main method to derive the RequirementProfile.
- `compute_context_sensitivity(context)`: Computes base privacy requirement score.
- `compute_tracking_risk(context, experiences)`: Computes the risk of tracking.
- `compute_correlation_risk(context, experiences)`: Computes the risk of multi-session correlation.

## Dependencies
- `capss.schemas.context.RegistrationContext`
- `capss.schemas.context.RequirementProfile`
- `capss.schemas.experience.Experience`

## Example Usage
```python
from capss.context_analyzer import ContextAnalyzer
from capss.schemas.context import RegistrationContext

analyzer = ContextAnalyzer()
profile = analyzer.analyze(context_obj, experiences_list)
print(profile.privacy_requirement)
```
