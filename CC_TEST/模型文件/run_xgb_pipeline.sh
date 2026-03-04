#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
MODEL_DIR="${ROOT_DIR}/CC_TEST/模型文件"
OUT_DIR="${MODEL_DIR}/out"

MANIFEST="${1:-${MODEL_DIR}/dataset_manifest.example.json}"
RUN_ID="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${OUT_DIR}/run_${RUN_ID}"
mkdir -p "${RUN_DIR}"

FLOW_CSV="${RUN_DIR}/flow_dataset.csv"
FLOW_META="${RUN_DIR}/flow_dataset_meta.json"

python3 "${MODEL_DIR}/build_flow_dataset.py" \
  --manifest "${MANIFEST}" \
  --out-csv "${FLOW_CSV}" \
  --out-meta "${FLOW_META}" \
  --min-packets-per-flow 3

python3 "${MODEL_DIR}/train_xgboost_shap.py" \
  --data "${FLOW_CSV}" \
  --out-dir "${RUN_DIR}" \
  --test-size 0.2 \
  --val-size 0.2 \
  --seed 42 \
  --n-estimators 500 \
  --max-depth 6 \
  --learning-rate 0.05 \
  --subsample 0.9 \
  --colsample-bytree 0.9 \
  --min-child-weight 1.0 \
  --shap-sample 300 \
  --shap-background 128 \
  --positive-label 1

echo "[ok] done: ${RUN_DIR}"
