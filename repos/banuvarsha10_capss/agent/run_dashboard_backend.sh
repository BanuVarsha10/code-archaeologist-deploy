#!/usr/bin/env bash
# Starts the CAPSS Dashboard backend with a sudo keep-alive running
# alongside it, so `sudo -n nr-ue` (used for every real registration launch)
# never fails due to the normal 15-minute sudo timestamp expiry mid-run.
#
# The keep-alive is scoped to THIS script's lifetime only: it runs in the
# background, and the `trap` below kills it the moment this script exits —
# whether that's you pressing Ctrl+C on the server, or the server crashing.
# Nothing is left running or loosened system-wide afterward. This does NOT
# touch /etc/sudoers or any system-wide sudo policy.
#
# Usage:
#   cd ~/5g-project/agent
#   ./run_dashboard_backend.sh
#
# You'll be prompted for your password once (by `sudo -v` below), then not
# again for the rest of this run.

set -e

# Loads GEMINI_API_KEY (LLM explainer task) if dashboard_backend/.env.local
# exists — gitignored, never committed. Its absence is not an error: the
# explainer degrades to silently omitting the AI summary (see
# dashboard_backend/llm_explainer.py's module docstring).
if [ -f dashboard_backend/.env.local ]; then
  set -a
  # shellcheck disable=SC1091
  source dashboard_backend/.env.local
  set +a
fi

sudo -v

(
  while sudo -n true 2>/dev/null; do
    sleep 60
  done
) &
KEEPALIVE_PID=$!

cleanup() {
  kill "$KEEPALIVE_PID" 2>/dev/null || true
}
trap cleanup EXIT

uvicorn dashboard_backend.main:app --reload
