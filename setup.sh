#!/usr/bin/env bash
# Reproducible project setup. Makes no system-wide changes and needs no root:
#   * creates .venv (bootstrapping pip if the distro lacks python3-venv/ensurepip)
#   * installs requirements.txt
#   * provides libgomp.so.1 for LightGBM from the Ubuntu .deb if it is not installed
#   * clones the Kubernetes dataset if missing
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
DATASET_URL="https://github.com/yigitsever/kubernetes-dataset"
DATASET_DIR="data/raw/kubernetes-dataset"

echo "[setup] python: $($PYTHON --version)"
if [ ! -x .venv/bin/python ]; then
    if "$PYTHON" -c "import ensurepip" 2>/dev/null; then
        "$PYTHON" -m venv .venv
    else
        echo "[setup] ensurepip unavailable; creating venv without pip and bootstrapping it"
        "$PYTHON" -m venv --without-pip .venv
        mkdir -p .cache
        curl -sSfL https://bootstrap.pypa.io/get-pip.py -o .cache/get-pip.py
        .venv/bin/python .cache/get-pip.py -q
    fi
fi
.venv/bin/python -m pip install -q --upgrade pip
.venv/bin/python -m pip install -q -r requirements.txt
echo "[setup] python packages installed"

if ldconfig -p 2>/dev/null | grep -q "libgomp.so.1 "; then
    echo "[setup] libgomp.so.1 found system-wide"
elif ls vendor/libgomp1/usr/lib/*/libgomp.so.1 >/dev/null 2>&1; then
    echo "[setup] using vendored libgomp in vendor/libgomp1"
else
    echo "[setup] libgomp.so.1 missing; extracting Ubuntu libgomp1 package into vendor/ (no root needed)"
    echo "        (alternative: sudo apt install libgomp1)"
    mkdir -p .cache/deb vendor
    (cd .cache/deb && apt-get download libgomp1)
    dpkg -x .cache/deb/libgomp1_*.deb vendor/libgomp1
fi
.venv/bin/python -c "from src.utils.native import import_lightgbm; print('[setup] lightgbm', import_lightgbm().__version__)"

if [ ! -d "$DATASET_DIR/.git" ]; then
    mkdir -p "$(dirname "$DATASET_DIR")"
    git clone --depth 1 "$DATASET_URL" "$DATASET_DIR"
fi
echo "[setup] dataset: $(ls "$DATASET_DIR"/benign/*.csv "$DATASET_DIR"/malicious/*.csv | wc -l) capture files"

mkdir -p data/processed captures/pcap captures/flows models logs reports
echo "[setup] done. Next: .venv/bin/python -m src.detection.train --model extratrees"
