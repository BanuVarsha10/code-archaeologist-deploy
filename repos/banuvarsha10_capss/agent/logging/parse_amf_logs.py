import os
import re
import csv

# --------------------------------------------------
# File Paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_LOG = os.path.join(BASE_DIR, "raw_logs", "amf.log")

LOG_FILE = os.environ.get(
    "CAPSS_LOG_FILE",
    DEFAULT_LOG
)

OUTPUT_DIR = os.path.join(BASE_DIR, "..", "datasets")
os.makedirs(OUTPUT_DIR, exist_ok=True)

OUTPUT_FILE = os.path.join(OUTPUT_DIR, "registration_dataset.csv")

# --------------------------------------------------
# Regular Expressions
# --------------------------------------------------

timestamp_re = re.compile(r"^(\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)")

suci_re = re.compile(r"(suci-[^\]\s]+)", re.IGNORECASE)

imsi_re = re.compile(r"(imsi-\d+)", re.IGNORECASE)

ip_re = re.compile(r"accepted\[(.*?)\]")

dnn_re = re.compile(r"DNN\[([^\]]+)\]")

snssai_re = re.compile(r"S_NSSAI\[([^\]]+)\]")

cause_re = re.compile(r"[Cc]ause[\[\(]([^\]\)]+)[\]\)]")

# --------------------------------------------------
# Variables
# --------------------------------------------------

records = []

current = None

last_gnb_ip = ""

request_counter = 0

# --------------------------------------------------
# Read Log
# --------------------------------------------------

with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as file:

    for line in file:

        # -------------------------------
        # Save gNB IP
        # -------------------------------

        if "gNB-N2 accepted" in line:

            ip = ip_re.search(line)

            if ip:
                last_gnb_ip = ip.group(1)

        # -------------------------------
        # Start Registration
        # -------------------------------

        if "InitialUEMessage" in line:

            # Save previous registration
            if current is not None:
                records.append(current)

            ts = timestamp_re.search(line)

            request_counter += 1

            current = {
                "Request_ID": "",
                "Timestamp": ts.group(1) if ts else "",
                "Event": "Registration",
                "UE_ID": "",
                "SUCI": "",
                "Authentication_Result": "",
                "Registration_Status": "",
                "Registration_Type": "INITIAL",
                "Cause_Code": "UNKNOWN",
                "gNB_IP": last_gnb_ip,
                "DNN": "",
                "S_NSSAI": ""
            }

            continue

        if current is None:
            continue

        # -------------------------------
        # SUCI
        # -------------------------------

        suci = suci_re.search(line)

        if suci:
            current["SUCI"] = suci.group(1)

        # -------------------------------
        # IMSI
        # -------------------------------

        imsi = imsi_re.search(line)

        if imsi:
            current["UE_ID"] = imsi.group(1)

        # -------------------------------
        # Authentication
        # -------------------------------

        if "Authentication failure" in line:

                current["Authentication_Result"] = "Failure"

                current["Cause_Code"] = "AUTH_FAILURE"

        if "Authentication successful" in line:

                current["Authentication_Result"] = "Success"

                current["Cause_Code"] = "SUCCESS"

        # -------------------------------
        # Registration Complete
        # -------------------------------

        if "Registration complete" in line:

            current["Registration_Status"] = "Success"
            current["Cause_Code"] = "SUCCESS"

        # -------------------------------
        # Cause Code (explicit cause in log line, overrides default)
        # -------------------------------

        cause = cause_re.search(line)

        if cause:
            current["Cause_Code"] = cause.group(1)

            if current["Authentication_Result"] == "":
                current["Authentication_Result"] = "Success"

            if current["Cause_Code"] == "UNKNOWN":
                current["Cause_Code"] = "SUCCESS"

        # -------------------------------
        # DNN
        # -------------------------------

        dnn = dnn_re.search(line)

        if dnn:
            current["DNN"] = dnn.group(1)

        # -------------------------------
        # Slice
        # -------------------------------

        snssai = snssai_re.search(line)

        if snssai:
            current["S_NSSAI"] = snssai.group(1)

# --------------------------------------------------
# Save Last Registration
# --------------------------------------------------

if current is not None:

    if current["Registration_Status"] == "":
        current["Registration_Status"] = "Failure"

    records.append(current)

# --------------------------------------------------
# Fill Default Successful Values
# --------------------------------------------------

for record in records:

    if record["Authentication_Result"] == "":
        record["Authentication_Result"] = "Success"

    if record["Registration_Status"] == "":
        record["Registration_Status"] = "Success"

    if record["Cause_Code"] == "UNKNOWN":
        record["Cause_Code"] = "SUCCESS"


# --------------------------------------------------
# Handle Unknown Subscribers
# --------------------------------------------------

for record in records:

    # If IMSI was never resolved but SUCI exists,
    # preserve the request by using the SUCI as the identifier.
    if record["UE_ID"] == "" and record["SUCI"] != "":

        record["UE_ID"] = record["SUCI"]

    # Registration failed because subscriber was unknown
    if record["Registration_Status"] == "Failure":

        record["Authentication_Result"] = "Failure"

        if record["Cause_Code"] == "SUCCESS":

            record["Cause_Code"] = "UNKNOWN_SUBSCRIBER"
# --------------------------------------------------
# Assign Request IDs
# --------------------------------------------------

for index, record in enumerate(records, start=1):

    record["Request_ID"] = f"REQ{index:06d}"

# --------------------------------------------------
# Write CSV
# --------------------------------------------------

with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:

    fieldnames = [

        "Request_ID",

        "Timestamp",

        "Event",

        "UE_ID",

        "SUCI",

        "Authentication_Result",

        "Registration_Status",

        "Registration_Type",

        "Cause_Code",

        "gNB_IP",

        "DNN",

        "S_NSSAI",

    ]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()

    writer.writerows(records)

print("----------------------------------------")
print("AMF Log Parsing Completed")
print(f"Registrations Found : {len(records)}")
print(f"CSV Saved : {OUTPUT_FILE}")
print("----------------------------------------")
