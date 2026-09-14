import csv
import os
from typing import List, Tuple, Optional
from datetime import datetime

from capss.schemas.context import RegistrationContext

class ContextLoader:
    def __init__(self, csv_path: str):
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"CSV file not found: {csv_path}")
        self.csv_path = csv_path
        self._records = []
        self._load_internal()

    def _load_internal(self):
        with open(self.csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                self._records.append(row)

    def load_all(self) -> List[RegistrationContext]:
        contexts = []
        for record in self._records:
            is_valid, errors = self.validate_record(record)
            if is_valid:
                # Convert timestamp
                ts_str = record.get('timestamp')
                try:
                    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f") if ts_str else datetime.now()
                except ValueError:
                    ts = datetime.now()

                ctx = RegistrationContext(
                    ue_id=record.get('ue_id', ''),
                    suci=record.get('suci', ''),
                    registration_type=record.get('registration_type', ''),
                    slice_type=record.get('slice_type', ''),
                    dnn=record.get('dnn', ''),
                    timestamp=ts,
                    privacy_score=float(record['privacy_score']) if record.get('privacy_score') else None,
                    attack_result=record.get('attack_result'),
                    correlation_score=float(record['correlation_score']) if record.get('correlation_score') else None,
                    metadata_leakage=float(record['metadata_leakage']) if record.get('metadata_leakage') else None,
                    threat_score=float(record['threat_score']) if record.get('threat_score') else None
                )
                contexts.append(ctx)
            else:
                print(f"Skipping invalid record: {errors}")
        return contexts

    def load_by_ue(self, ue_id: str) -> List[RegistrationContext]:
        return [ctx for ctx in self.load_all() if ctx.ue_id == ue_id]

    def load_by_slice(self, slice_type: str) -> List[RegistrationContext]:
        return [ctx for ctx in self.load_all() if ctx.slice_type == slice_type]

    def load_by_time_range(self, start: datetime, end: datetime) -> List[RegistrationContext]:
        return [ctx for ctx in self.load_all() if start <= ctx.timestamp <= end]

    def validate_record(self, record: dict) -> Tuple[bool, List[str]]:
        errors = []
        required_fields = ['ue_id', 'suci', 'registration_type', 'slice_type', 'dnn', 'timestamp']
        for field in required_fields:
            if not record.get(field):
                errors.append(f"Missing required field: {field}")
        
        return len(errors) == 0, errors

    def get_unique_ues(self) -> List[str]:
        return list(set(r.get('ue_id') for r in self._records if r.get('ue_id')))

    def get_summary(self) -> dict:
        total = len(self._records)
        ues = self.get_unique_ues()
        reg_types = {}
        slices = {}
        for r in self._records:
            rt = r.get('registration_type')
            if rt:
                reg_types[rt] = reg_types.get(rt, 0) + 1
            st = r.get('slice_type')
            if st:
                slices[st] = slices.get(st, 0) + 1
        
        return {
            "total_records": total,
            "unique_ues": len(ues),
            "registration_types": reg_types,
            "slices": slices
        }
