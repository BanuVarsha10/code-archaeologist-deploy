"""
CAPSS

Mixed Traffic Generator

Runs multiple attack generators according
to systems/configs/mixed_traffic.json
"""

import json
import subprocess
from pathlib import Path

# ==========================================================
# Paths
# ==========================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

CONFIG = (
    PROJECT_ROOT
    / "systems"
    / "configs"
    / "mixed_traffic.json"
)

SCRIPTS = (
    PROJECT_ROOT
    / "systems"
    / "scripts"
)

# ==========================================================
# Config
# ==========================================================

with open(CONFIG) as f:

    config = json.load(f)

traffic = config["traffic"]

# ==========================================================
# Helper
# ==========================================================


def run_script(script_name):

    script = SCRIPTS / script_name

    subprocess.run(

        ["python3", str(script)],

        check=True

    )


# ==========================================================
# Start
# ==========================================================

print("=" * 60)
print("Mixed Traffic Generator")
print("=" * 60)

subprocess.run(["sudo", "-v"], check=True)

# ==========================================================
# Normal Traffic
# ==========================================================

print("\nLaunching Normal UEs\n")

subprocess.run(

    [

        "python3",

        str(SCRIPTS / "start_multiple_ues.py"),

        "--count",

        str(traffic["normal"])

    ],

    check=True

)

# ==========================================================
# Duplicate
# ==========================================================

for i in range(traffic["duplicate"]):

    print(f"\nDuplicate Attack {i+1}")

    run_script("start_duplicate_attack.py")

# ==========================================================
# Invalid Subscriber
# ==========================================================

for i in range(traffic["invalid_subscriber"]):

    print(f"\nInvalid Subscriber {i+1}")

    run_script("start_invalid_subscriber.py")

# ==========================================================
# Registration Flood
# ==========================================================

for i in range(traffic.get("registration_flood", 0)):

    print(f"\nRegistration Flood {i+1}")

    run_script("start_registration_flood.py")

print("\nMixed Traffic Finished.")