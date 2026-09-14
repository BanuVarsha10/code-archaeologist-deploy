from pathlib import Path
import shutil

BASE = Path.home() / "5g-project" / "UERANSIM" / "config"

SOURCE = BASE / "open5gs-ue.yaml"
OUTPUT = BASE / "generated"

OUTPUT.mkdir(parents=True, exist_ok=True)

template = SOURCE.read_text()

for i in range(1, 21):

    imsi = f"999700000000{i:03d}"

    text = template.replace(
        "imsi-999700000000001",
        f"imsi-{imsi}"
    )

    outfile = OUTPUT / f"ue{i:03d}.yaml"

    outfile.write_text(text)

    print(f"Created {outfile.name}")
