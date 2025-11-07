#!/usr/bin/env bash
set -euo pipefail

# Install tshark non-interactively for PyShark
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark

# Python deps (hosted pins)
pip install -r requirements-hosted.txt

# Verify uvicorn installed (module form)
python -c "import uvicorn, sys; print('uvicorn module OK, version:', getattr(uvicorn, '__version__', 'unknown'))" || true

# Sanity check (optional)
which tshark || true
(tshark -v || true)
echo "Build script completed." 

python -m pip install --upgrade pip setuptools wheel