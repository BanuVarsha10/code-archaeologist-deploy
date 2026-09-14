# CAPSS — Context-Aware Adaptive Privacy and Security System

## 1. What this project is

CAPSS is an autonomous AI agent that recommends and adapts a privacy/security
scheme for every 5G UE (device) registration in real time. Three real modules
feed one reasoning pipeline:

- **Systems** (`agent/systems/`) — classifies each registration request
  (replay, duplicate registration, flooding, invalid subscriber, mixed) and
  produces a threat classification.
- **Privacy** (`agent/privacy/`) — scores each registration's privacy risk
  (metadata leakage, correlation/linkability, overall privacy score).
- **CAPSS Agent** (`agent/capss/`) — combines both real-time modules with the
  UE's own experience history and cross-UE retrieval (RAG) to select (and,
  when useful, hybridize) a cryptographic privacy scheme from a knowledge
  base of 7 real schemes (ECIES, ML-KEM, Group Signatures, Differential
  Privacy, ZKP, SUPI Rearrangement, and hybrids), then validates and executes
  it.

On top of that pipeline sits a full-stack **dashboard**
(`agent/dashboard_backend/` + `dashboard_frontend/`) that drives the same,
unmodified pipeline against **real** Open5GS + UERANSIM + MongoDB
infrastructure — "Live Mode" is the dashboard's only mode; every
registration it shows is a real 5G registration, not a simulation.

## 2. Prerequisites

Verified against this project's actual environment (WSL2 Ubuntu 22.04):

| Component | Version confirmed in this environment |
|---|---|
| WSL2 + Ubuntu 22.04 | required — all backend/hardware commands below must run **inside WSL**, not PowerShell/cmd, and not via a `\\wsl.localhost\...` UNC path as a shell's working directory (see Troubleshooting) |
| Python | 3.10.12 (`python3 --version`) |
| pip | 22.0.2 — this environment has **no** PEP 668 "externally managed" restriction, so plain `pip install ...` works; you do **not** need `--break-system-packages` here (only add it if your own pip refuses with an `externally-managed-environment` error) |
| Node.js | a **WSL-native** LTS build (18+) — see the note below, this is not optional |
| cmake | 3.22.1 — needed to build UERANSIM and to build `liboqs-python`'s underlying C library |
| MongoDB | reachable at `mongodb://localhost:27017/`, database `open5gs`, collection `subscribers` (Open5GS's own subscriber store — CAPSS's Systems module reads it directly) |
| Open5GS | installed with its 9 core daemons available via systemd: `open5gs-nrfd`, `open5gs-amfd`, `open5gs-smfd`, `open5gs-upfd`, `open5gs-ausfd`, `open5gs-udmd`, `open5gs-udrd`, `open5gs-pcfd`, `open5gs-nssfd` |
| UERANSIM | **not part of this repo** — its own separate clone of [github.com/aligungr/UERANSIM](https://github.com/aligungr/UERANSIM) at `~/5g-project/UERANSIM`, built with `make` (see below) |
| Gemini API key | only needed for the dashboard's optional AI-generated explanation text — the rest of the system works without it |

**Node.js must be a WSL-native install, not the Windows-side Node.js.**
`dashboard_frontend/node_modules` was installed against Linux (its
`@rollup/*` native binding is `rollup-linux-x64-gnu`), so running `npm`/`vite`
via a Windows-installed `node.exe` against these files fails with
`Cannot find module '@rollup/rollup-win32-x64-msvc'` — the packages simply
don't exist for the platform running them. Install Node inside WSL, e.g.:
```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
# open a new WSL shell, then:
nvm install --lts
```

Real pip dependencies actually imported by this project (confirmed by
grepping every real import in `capss/`, `systems/`, `privacy/`,
`dashboard_backend/`, and the top-level scripts — `agent/requirements.txt`
itself only lists `pydantic`/`pytest` and is stale, so install this full
list instead):
```bash
pip install pydantic pytest fastapi uvicorn pymongo cryptography pandas numpy matplotlib openpyxl requests liboqs-python
```
(`liboqs-python`'s install builds the real `liboqs` C library via `cmake`
automatically — that's what `cmake` above is for, alongside UERANSIM's own
build. If it fails to build, install a C/C++ toolchain — `build-essential`
— first.)

## 3. One-time setup

Run everything below from inside a real WSL shell (`wsl.exe -d Ubuntu-22.04`
or a native WSL terminal), never from PowerShell against a
`\\wsl.localhost\...` path.

```bash
# 1. Python dependencies
cd ~/5g-project/agent
pip install pydantic pytest fastapi uvicorn pymongo cryptography pandas numpy matplotlib openpyxl requests liboqs-python

# 2. Clone and build UERANSIM (not part of this repo — see Prerequisites)
cd ~/5g-project
git clone https://github.com/aligungr/UERANSIM.git
cd UERANSIM
make

# 3. Frontend dependencies (from a WSL-native Node — see Prerequisites)
cd ~/5g-project/dashboard_frontend
npm install

# 4. Gemini API key for the dashboard's optional AI explanation text
#    (everything else works without this — the explainer just omits the
#    AI summary if it's absent)
echo "GEMINI_API_KEY=your-key-here" > ~/5g-project/agent/dashboard_backend/.env.local
```

Open5GS + MongoDB installation itself follows the standard Open5GS
installation guide for your distribution (not part of this repo — the repo
assumes a working Open5GS + MongoDB install and only *talks* to it).
Subscriber provisioning is **not** a manual one-time step: the dashboard
provisions/removes subscribers in MongoDB itself, per device, via
`open5gs-dbctl` at run time (see `agent/dashboard_backend/live_mode.py`) —
you only need Open5GS + MongoDB running first.

## 4. How to run

### (a) Backend-only / test-only (no hardware required)

```bash
cd ~/5g-project/agent

# Full test suite (409 tests: 241 core capss/systems/privacy tests +
# 168 dashboard_backend tests)
python3 -m pytest -q

# Real, non-simulated demo of Systems -> Privacy -> Agent on synthetic
# registration traffic (no Open5GS/UERANSIM required)
python3 demo_for_mentor.py
```

### (b) Full dashboard, Live Mode (real Open5GS/UERANSIM hardware)

Live Mode is the dashboard's only mode — there is no simulated fallback.
You need Open5GS + MongoDB already running, and UERANSIM already built
(Section 3).

```bash
# 1. Start the gNB (separate terminal, stays running)
cd ~/5g-project/agent
sudo ~/5g-project/agent/systems/scripts/start_gnb.sh
# or directly: sudo ~/5g-project/UERANSIM/build/nr-gnb -c ~/5g-project/UERANSIM/config/open5gs-gnb.yaml

# 2. Confirm Open5GS's 9 core services are active
~/5g-project/agent/systems/scripts/check_core.sh

# 3. Start the backend (from agent/ — imports resolve the same way
#    demo_for_mentor.py's do). run_dashboard_backend.sh caches your sudo
#    credential (needed because every real device registration launches
#    `sudo nr-ue`) so you're prompted once, not per device:
cd ~/5g-project/agent
./run_dashboard_backend.sh
# equivalent to: sudo -v && uvicorn dashboard_backend.main:app --reload

# 4. Start the frontend (separate terminal, from dashboard_frontend/,
#    using a WSL-native Node — see Prerequisites)
cd ~/5g-project/dashboard_frontend
npm run dev
```

Open the URL `npm run dev` prints (Vite's default is `http://localhost:5173`).

## 5. Running tests

```bash
cd ~/5g-project/agent
python3 -m pytest -q
```
409 tests, confirmed passing in this environment. If you ever see a
pytest plugin-loading crash mentioning `langsmith`/`uuid_utils` (this can
happen if an unrelated LLM-tooling package that ships a pytest plugin gets
installed into the same environment — it does **not** occur in this
project's own dependency set, confirmed directly: `langsmith`/`uuid_utils`
aren't installed here and the suite collects and runs cleanly without any
workaround), the fix is:
```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -q
```

Dashboard-only test subset:
```bash
python3 -m pytest dashboard_backend/tests/ -q   # 168 tests
```

## 6. Ablation study / stress test scripts

Both are real runner scripts under `agent/dashboard_backend/scripts/`, run
as modules from `agent/`:

```bash
cd ~/5g-project/agent

# Ablation study: runs a batch of real scenarios through the full real
# pipeline 4x each (Full CAPSS, no_threat, no_privacy, no_experience),
# reports per-scenario detail + aggregate disagreement rates to a JSON
# file under dashboard_backend/scripts/ablation_study_results/
python3 -m dashboard_backend.scripts.ablation_study --num-scenarios 20 --seed 42

# Real-hardware scaling stress test: finds the real batch-size capacity
# limit against actual Open5GS/UERANSIM/MongoDB (needs Live Mode
# prerequisites from Section 4b — real hardware, real sudo)
python3 -m dashboard_backend.scripts.stress_test --start 5 --step 5 --max 100
```

## 7. Project structure

```
5g-project/
├── README.md                    This file.
├── UERANSIM/                    Not in this repo — separate clone of github.com/aligungr/UERANSIM (gNB/UE simulator), built via `make`.
├── agent/                       The whole Python backend project (run everything from here).
│   ├── capss/                   Core reasoning agent — context analysis, scoring, RAG, policy generation. (protected/core)
│   ├── systems/                 Pre-AMF threat classification module + hardware orchestration scripts. (protected/core)
│   ├── privacy/                 Live privacy/metadata/correlation scoring module. (protected/core)
│   ├── data/                    Knowledge base (`privacy_schemes.json`) and sample datasets. (protected/core)
│   ├── tests/                   Core test suite for capss/systems/privacy (241 tests). (protected/core)
│   ├── logging/                 AMF log parsing (`parse_amf_logs.py`).
│   ├── configs/                 Scoring weights/thresholds JSON.
│   ├── scripts/                 General-purpose project utilities (CSV export, user-flow demo).
│   ├── dashboard_backend/       FastAPI backend driving the real Live Mode dashboard.
│   │   ├── main.py              API routes.
│   │   ├── pipeline_service.py  Real per-device Live Mode flow + read-only recommendation helper.
│   │   ├── live_mode.py         Real Open5GS/UERANSIM subprocess orchestration.
│   │   ├── scripts/             ablation_study.py, stress_test.py — batch/real-hardware runner scripts.
│   │   └── tests/               Dashboard backend test suite (168 tests).
│   ├── build_capss.py, run_agent.py, run_integrated_flow.py, demo_for_mentor.py, run_dashboard_backend.sh
│   │                             Top-level entrypoint scripts — run from `agent/`.
│   └── requirements.txt         Partial — see Section 2 for the real, complete dependency list.
└── dashboard_frontend/          React + TypeScript + Vite dashboard UI.
    ├── src/panels/               One panel per dashboard feature (Attack Testing, Assessment, Explainability, ...).
    ├── src/api/                  Typed fetch client for the FastAPI backend.
    └── package.json              `npm run dev` / `npm run build`.
```

`capss/`, `systems/`, `privacy/`, `agent/tests/`, and `data/` are treated as
protected core — verified untouched (byte-for-byte hash-identical) across
this session's ablation-study and reorganization work, aside from the two
files the ablation feature was explicitly authorized to extend:
`capss/context_analyzer/analyzer.py` and `capss/reasoning/engine.py`.

## 8. Troubleshooting

- **`ModuleNotFoundError` / import errors when running `uvicorn` or
  `pytest`** — you're not running from `agent/`. Every backend entrypoint
  resolves imports (`from capss...`, `from systems...`,
  `from dashboard_backend...`) relative to `agent/` as the working
  directory — `cd ~/5g-project/agent` first.

- **`Cannot find module '@rollup/rollup-win32-x64-msvc'` (or any other
  `@rollup/rollup-*` platform package) when running `npm run dev`/`build`**
  — you're running `npm`/`node`/`vite` via a Windows-installed Node against
  WSL-hosted `node_modules`. This project's `node_modules` was installed
  from a Linux-native Node (its `@rollup` binding is
  `rollup-linux-x64-gnu`), which a Windows `node.exe` can never satisfy —
  no reinstall from Windows fixes this, and attempting `npm install` from
  Windows against this WSL-native, symlinked `node_modules` tree can fail
  outright (`EISDIR` on `lstat` of the `.bin/` symlinks — Windows can't
  `lstat` WSL's POSIX symlinks over `\\wsl.localhost\...`). Always run
  `npm`/`node`/`vite` from **inside WSL**, using a Node installed **inside**
  WSL (see Prerequisites).

- **Running commands from PowerShell against `\\wsl.localhost\Ubuntu-22.04\...`
  paths** — file *editing* tools can use this path fine, but *running*
  commands (uvicorn, pytest, npm, sudo-based hardware scripts) from
  PowerShell/cmd against that path is unreliable (cmd.exe can't even use a
  UNC path as a working directory) and, for anything sudo-based, simply
  won't have the real Linux `sudo` context. Always run backend/hardware
  commands from an actual WSL shell.

- **`sudo: a password is required` when starting a Live Mode registration**
  — every real device registration launches `sudo nr-ue`. Run
  `./run_dashboard_backend.sh` (Section 4b) rather than `uvicorn` directly —
  it runs `sudo -v` once up front and keeps your sudo timestamp alive with a
  background keep-alive for the life of the server, so you're never
  prompted mid-run.

- **`Cannot find Requested NSSAI` during a real registration** — a real
  slice (SST/SD) mismatch between the gNB config, the AMF config, and the
  UE config; all three must agree. This project already fixed the one
  concrete way this used to happen here: subscriber provisioning used to
  hardcode SST/SD separately from `UERANSIM/config/open5gs-ue.yaml`, which
  could silently drift out of sync after a gNB/AMF config change.
  `dashboard_backend/live_mode.py`'s `get_dbctl_slice()` now reads SST/SD
  **live** from that same UE config template every time, so dbctl
  provisioning and the UE's own request can never disagree. If you edit
  `open5gs-gnb.yaml`'s or `/etc/open5gs/amf.yaml`'s slice, update
  `UERANSIM/config/open5gs-ue.yaml` to match — that's the only file that
  needs to change.

- **A `langsmith`/`uuid_utils` pytest plugin conflict** — see Section 5.
  Not present in this project's own dependency set as verified; only
  relevant if some other package's pytest plugin gets installed alongside
  it.
