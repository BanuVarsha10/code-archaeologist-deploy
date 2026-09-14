# Context Loader Module

The `context_loader` package ingests 5G registration datasets and populates `RegistrationContext` objects for downstream processing by the Context Analyzer and Reasoning Engine.

It provides two loaders:
1. `ContextLoader` (`loader.py`): Ingests single simplified registration CSV files.
2. `SystemsContextLoader` (`systems_loader.py`): Ingests raw paired Systems-module CSV batches (`registration_dataset.csv` & `attack_dataset.csv`), performing automatic joins and strict security field validation.

---

## Classes & Functions

### `SystemsContextLoader` (`systems_loader.py`)

Ingests and joins raw Systems-module CSV pairs directly without manual pre-processing.

#### CSV Input Schemas:
- **`registration_dataset.csv`**: `Request_ID, Timestamp, Event, UE_ID, SUCI, Authentication_Result, Registration_Status, Registration_Type, Cause_Code, gNB_IP, DNN, S_NSSAI`
- **`attack_dataset.csv`**: `Request_ID, Experiment, Timestamp, UE_ID, Attack_Detected, Attack_Type, Decision, Severity, Confidence, Risk_Score, Reasons`

#### Join & Mapping Logic:
- Joins on `Request_ID` (with fallback to `(UE_ID, Timestamp)`).
- Maps fields to `RegistrationContext`:
  - `UE_ID` → `ue_id`
  - `SUCI` → `suci`
  - `Registration_Type` → `registration_type`
  - `S_NSSAI` → `slice_type`
  - `DNN` → `dnn`
  - `Timestamp` → `timestamp` (datetime ISO 8601)
  - `Decision` → `request_classification` (enforced ALLOW / TAG / BLOCK)
  - `Attack_Type` → `attack_type` (set to `"NONE"` if `Attack_Detected` is False)
  - `Severity` → `attack_severity`
  - `Confidence` → `detection_confidence` (float)
  - `Risk_Score` → `threat_score` (float)
  - `Reasons` → `validation_results` (dict) and `reasons` (raw string)
- Uncomputed Privacy-module fields (`privacy_score`, `privacy_risk_level`, `metadata_leakage`, `correlation_score`) remain `None`.

#### Validation Rules:
- `request_classification` must be one of `ALLOW`, `TAG`, `BLOCK` (raises `ValueError` with `Request_ID` if invalid).
- Mandatory fields (`UE_ID`, `SUCI`, `Timestamp`, `Decision`) must be non-empty (raises `ValueError` with `Request_ID` if missing).
- Numeric fields (`Confidence`, `Risk_Score`) must parse as float if present (raises `ValueError` with `Request_ID` if invalid).

#### Methods:
- `load_all()`: Returns list of joined and validated `RegistrationContext` objects.
- `load_by_ue(ue_id)`: Filter contexts by UE ID.
- `load_by_classification(classification)`: Filter contexts by request classification (`ALLOW`, `TAG`, `BLOCK`).
- `get_summary()`: Statistical summary of loaded batch.

---

### `ContextLoader` (`loader.py`)

Legacy loader for single CSV registration logs.

---

## Dependencies
- `csv`, `os`, `datetime`
- `capss.schemas.context.RegistrationContext`

## Example Usage

```python
from capss.context_loader import SystemsContextLoader, load_systems_contexts

# Load paired Systems CSVs directly
loader = SystemsContextLoader(
    registration_csv_path="data/registration_dataset.csv",
    attack_csv_path="data/attack_dataset.csv"
)

contexts = loader.load_all()
summary = loader.get_summary()

# Or using convenience function
contexts = load_systems_contexts("registration.csv", "attack.csv")
```
