import argparse
import subprocess
import time
from pathlib import Path

# ==========================================================
# Paths
# ==========================================================

UERANSIM = Path.home() / "5g-project" / "UERANSIM"

CONFIGS = UERANSIM / "config" / "generated"

NR_UE = UERANSIM / "build" / "nr-ue"

# ==========================================================
# Arguments
# ==========================================================

parser = argparse.ArgumentParser()

parser.add_argument(

    "--count",

    type=int,

    default=20,

    help="Number of UEs to launch"

)

parser.add_argument(
    "--exit-after-launch",
    action="store_true",
    help="Launch UEs and return immediately"
)

args = parser.parse_args()

# ==========================================================
# Authenticate once
# ==========================================================

print("Authenticating sudo once...")

subprocess.run(

    ["sudo", "-v"],

    check=True

)

processes = []

print("=" * 60)

print("Launching Multiple UEs")

print("=" * 60)

# ==========================================================
# Launch UEs
# ==========================================================

for i in range(1, args.count + 1):

    cfg = CONFIGS / f"ue{i:03d}.yaml"

    if not cfg.exists():

        print(f"Missing config: {cfg}")

        break

    print(f"Starting UE {i:02d} ({cfg.name})")

    p = subprocess.Popen([

        "sudo",

        "-n",

        str(NR_UE),

        "-c",

        str(cfg)

    ])

    processes.append(p)

    time.sleep(1)

print()

print(f"{len(processes)} UE processes launched.")

print("Leave this terminal running.")

print("Press Ctrl+C when experiment finishes.")

try:

    while True:

        time.sleep(1)

except KeyboardInterrupt:

    print("\nStopping UEs...")

    subprocess.run([

        "sudo",

        "pkill",

        "-f",

        "nr-ue"

    ])

    print("Done.")