# Policy Generator Module

## Purpose
Generates and validates PrivacyPolicies based on Recommendations and RegistrationContexts.

## Classes
- `PolicyGenerator`: Creates a `PrivacyPolicy`.
- `PolicyValidator`: Validates the generated policy against the knowledge base.

## Usage
```python
from capss.policy_generator import PolicyGenerator, PolicyValidator
generator = PolicyGenerator()
policy = generator.generate(recommendation, context)
```
