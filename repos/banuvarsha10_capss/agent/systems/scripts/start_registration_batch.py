import subprocess
import time
from pathlib import Path

BASE_DIR = Path.home() / "5g-project"

CONFIG_DIR = BASE_DIR / "UERANSIM" / "config" / "generated"

UE_BINARY = BASE_DIR / "UERANSIM" / "build" / "nr-ue"


def run_registration(index):

    config = CONFIG_DIR / f"ue{index:03d}.yaml"

    print("=" * 50)
    print(f"Registering UE {index:03d}")
    print("=" * 50)

    process = subprocess.Popen([
        "sudo",
        str(UE_BINARY),
        "-c",
        str(config)
    ])

    # Allow time for registration
    time.sleep(6)

    # Stop the UE cleanly
    process.terminate()

    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()

    print(f"UE {index:03d} completed.\n")

    time.sleep(2)


def main():

    count = 10

    print("\nSequential Registration Batch\n")

    subprocess.run(["sudo", "-v"])

    for i in range(1, count + 1):
        run_registration(i)

    print("=" * 50)
    print("Batch Completed")
    print("=" * 50)


if __name__ == "__main__":
    main()

