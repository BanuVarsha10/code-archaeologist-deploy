import re
import csv
import os
from typing import Optional, List
from datetime import datetime

class LogConverter:
    def __init__(self):
        # Example pattern: [2024-01-15 10:30:00.123] [amf] [info] Registration Request from UE [suci:suci-0-001-01-...] [type:initial] [slice:eMBB] [dnn:internet]
        self.pattern = re.compile(
            r"\[(.*?)\]\s+\[.*?\]\s+\[.*?\]\s+Registration Request from UE\s+\[suci:(.*?)\]\s+\[type:(.*?)\]\s+\[slice:(.*?)\]\s+\[dnn:(.*?)\]"
        )
        # Optional patterns for other fields
        self.ue_id_pattern = re.compile(r"ue_id:([a-zA-Z0-9-]+)")

    def convert_log_file(self, log_path: str, output_path: str) -> str:
        if not os.path.exists(log_path):
            raise FileNotFoundError(f"Log file not found: {log_path}")

        records = []
        with open(log_path, 'r', encoding='utf-8') as f:
            for line in f:
                parsed = self.parse_log_entry(line)
                if parsed:
                    records.append(parsed)

        if records:
            fieldnames = ['timestamp', 'ue_id', 'suci', 'registration_type', 'slice_type', 'dnn']
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for r in records:
                    row = {k: r.get(k) for k in fieldnames}
                    writer.writerow(row)
        
        return output_path

    def parse_log_entry(self, line: str) -> Optional[dict]:
        match = self.pattern.search(line)
        if match:
            timestamp_str, suci, reg_type, slice_type, dnn = match.groups()
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                timestamp = timestamp_str # Fallback

            # Try to extract ue_id, fallback to suci
            ue_match = self.ue_id_pattern.search(line)
            ue_id = ue_match.group(1) if ue_match else suci

            return {
                "timestamp": timestamp_str,
                "ue_id": ue_id,
                "suci": suci,
                "registration_type": reg_type,
                "slice_type": slice_type,
                "dnn": dnn
            }
        return None

    def parse_log_block(self, lines: List[str]) -> List[dict]:
        results = []
        for line in lines:
            parsed = self.parse_log_entry(line)
            if parsed:
                results.append(parsed)
        return results
