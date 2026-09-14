import subprocess
from pathlib import Path

# =====================================================
# Paths
# =====================================================

UERANSIM = Path.home() / "5g-project" / "UERANSIM"

NR_UE = UERANSIM / "build" / "nr-ue"

CONFIG = (
    UERANSIM
    / "config"
    / "generated"
    / "invalid_subscriber.yaml"
)

# =====================================================
# Attack
# =====================================================

print("=" * 60)
print("Invalid Subscriber Attack")
print("=" * 60)

print("Authenticating sudo...")
subprocess.run(["sudo", "-v"], check=True)

print("\nStarting Invalid Subscriber UE...\n")

subprocess.run([
    "sudo",
    str(NR_UE),
    "-c",
    str(CONFIG)
])

print("\nAttack Finished.")