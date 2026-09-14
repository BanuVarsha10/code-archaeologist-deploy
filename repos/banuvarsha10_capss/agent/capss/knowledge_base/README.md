# Knowledge Base Module

The `SchemeKnowledgeBase` loads and manages the predefined `PrivacyScheme` configurations from a JSON file.

## Classes
- `SchemeKnowledgeBase`: Manages the available privacy schemes.

### Methods:
- `get_scheme(scheme_id)`: Lookup scheme by ID.
- `get_by_name(name)`: Lookup by full name.
- `get_by_short_name(short_name)`: Lookup by short name.
- `get_all_schemes()`: Returns all schemes.
- `get_scheme_count()`: Returns the total count of loaded schemes.
- `filter_by_capability(capability)`: Filters schemes by supported capabilities.
- `filter_quantum_resistant()`: Filters quantum resistant schemes.
- `filter_by_context_preference(**kwargs)`: Filters schemes matching context preferences.
- `get_compatible_hybrids(scheme_id)`: Returns compatible hybrid schemes.
- `get_knowledge_version()`: Returns version of the knowledge base.
- `get_knowledge_coverage(requirement_profile)`: Calculates how well the loaded schemes cover the requirement dimensions.

## Dependencies
- `json`, `os`
- `capss.schemas.scheme.PrivacyScheme`

## Example Usage
```python
from capss.knowledge_base import SchemeKnowledgeBase

kb = SchemeKnowledgeBase("privacy_schemes.json")
scheme = kb.get_by_short_name("SUCI-NULL")
```
