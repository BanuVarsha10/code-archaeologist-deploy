import json
from pathlib import Path


class PolicyLoader:

    def load(self, file_path: str):

        with open(file_path) as f:
            policies = json.load(f)

        if isinstance(policies, list):
            return policies

        return [policies]