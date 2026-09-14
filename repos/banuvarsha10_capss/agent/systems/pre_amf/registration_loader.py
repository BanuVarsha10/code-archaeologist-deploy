"""
CAPSS - Context-Aware Privacy Protection and Scheme Selection

File:
    registration_loader.py

Purpose
-------
Loads registration_dataset.csv and converts every row
into RegistrationRequest objects.

This acts as the bridge between

parse_amf_logs.py

        ↓

registration_dataset.csv

        ↓

Pre-AMF Security Layer
"""

import csv
from datetime import datetime
from pathlib import Path

from systems.pre_amf.models import (
    RegistrationRequest,
)


# ==========================================================
# Registration Loader
# ==========================================================

class RegistrationLoader:
    """
    Loads registration records from CSV.
    """

    def __init__(self, csv_file):

        self.csv_file = Path(csv_file)

    # ======================================================
    # Load CSV
    # ======================================================

    def load(self):

        requests = []

        if not self.csv_file.exists():

            raise FileNotFoundError(

                f"Registration dataset not found: {self.csv_file}"

            )

        with open(

            self.csv_file,

            "r",

            newline="",

            encoding="utf-8"

        ) as csvfile:

            reader = csv.DictReader(csvfile)

            for row in reader:

                request = RegistrationRequest(

                    request_id=row["Request_ID"],

                    timestamp=self.parse_timestamp(
                        row["Timestamp"]
                    ),

                    ue_id=row["UE_ID"],

                    suci=row["SUCI"],

                    event=row["Event"],

                    authentication_result=row[
                        "Authentication_Result"
                    ],

                    registration_status=row[
                        "Registration_Status"
                    ],

                    gnb_ip=row["gNB_IP"],

                    dnn=row["DNN"],

                    snssai=row["S_NSSAI"],

                    registration_type=row.get(
                        "Registration_Type",
                        "INITIAL"
                    ),

                    cause_code=row.get(
                        "Cause_Code",
                        "SUCCESS"
                    ),

                    experiment_name=row.get(
                    "Experiment",
                    "NORMAL"),

                    attack_label="NONE",

                    attack_type="NONE",

                )

                requests.append(request)

        return requests

    # ======================================================
    # Timestamp Parser
    # ======================================================

    @staticmethod
    def parse_timestamp(timestamp):

        if not timestamp:

            return datetime.now()

        try:

            return datetime.strptime(

                timestamp,

                "%m/%d %H:%M:%S.%f"

            )

        except ValueError:

            return datetime.now()


# ==========================================================
# Convenience Function
# ==========================================================

def load_registration_dataset(csv_file):

    loader = RegistrationLoader(csv_file)

    return loader.load()