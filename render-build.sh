#!/usr/bin/env bash
set -euo pipefail

# Install tshark non-interactively for PyShark
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark

# Ensure we're installing into the same Python environment Render will use
which python || true
python -V || true
python -c "import sys; print('python exe:', sys.executable)" || true

# Upgrade pip tooling inside this Python and install deps (hosted pins)
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements-hosted.txt

# Verify uvicorn installed (module form) and show pip context
python -m pip --version || true
python -c "import uvicorn, sys; print('uvicorn module OK, version:', getattr(uvicorn, '__version__', 'unknown')); print('site:', sys.path[:3])" || true

# Sanity check (optional)
which tshark || true
(tshark -v || true)
echo "Build script completed." 