#!/usr/bin/env python3
"""
Train XGBoost + SHAP on flow-level QUIC traffic features.

Research intent:
- Build an explainable detector for encrypted/covert traffic analysis.
- Keep features in flow-level tabular form to align with recent IDS papers.

Inputs:
- flow_dataset.csv produced by build_flow_dataset.py

Outputs:
- metrics.json               : quantitative performance
- model_xgboost.json         : serialized model
- feature_importance_gain.csv: model-native gain importance
- shap_mean_abs.csv          : SHAP global importance (mean |value|)
- shap_beeswarm.png          : SHAP summary (distribution)
- shap_bar.png               : SHAP summary (bar)
- test_predictions.csv       : per-flow prediction for error analysis
"""

from __future__ import annotations

import argparse
import json
import warnings
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

try:
    import xgboost as xgb
except Exception as exc:  # pragma: no cover
    raise SystemExit(
        "[error] xgboost is required. Install with: python3 -m pip install xgboost"
    ) from exc

try:
    import shap
except Exception as exc:  # pragma: no cover
    raise SystemExit(
        "[error] shap is required. Install with: python3 -m pip install shap matplotlib"
    ) from exc


NON_FEATURE_COLS = {
    "label",
    "source_name",
    "flow_key",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train XGBoost + SHAP with flow-level dataset.")
    p.add_argument("--data", required=True, help="Flow dataset CSV path.")
    p.add_argument("--out-dir", required=True, help="Output directory.")
    p.add_argument("--test-size", type=float, default=0.2, help="Test split ratio (default: 0.2).")
    p.add_argument("--val-size", type=float, default=0.2, help="Validation ratio inside train split (default: 0.2).")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--n-estimators", type=int, default=500)
    p.add_argument("--max-depth", type=int, default=6)
    p.add_argument("--learning-rate", type=float, default=0.05)
    p.add_argument("--subsample", type=float, default=0.9)
    p.add_argument("--colsample-bytree", type=float, default=0.9)
    p.add_argument("--min-child-weight", type=float, default=1.0)
    p.add_argument("--early-stopping-rounds", type=int, default=40)
    p.add_argument(
        "--shap-sample",
        type=int,
        default=300,
        help="Max number of test samples used in SHAP plotting (default: 300).",
    )
    p.add_argument(
        "--shap-background",
        type=int,
        default=128,
        help="Background rows for permutation SHAP fallback (default: 128).",
    )
    p.add_argument(
        "--positive-label",
        type=int,
        default=1,
        help="Positive class label value (default: 1).",
    )
    return p.parse_args()


def load_dataset(path: Path, positive_label: int) -> Tuple[pd.DataFrame, pd.Series, List[str]]:
    df = pd.read_csv(path)
    if "label" not in df.columns:
        raise ValueError("dataset must contain 'label' column")

    y = (df["label"].astype(int) == int(positive_label)).astype(int)
    if y.nunique() < 2:
        raise ValueError("dataset must contain at least two classes for supervised training")

    feature_cols = [c for c in df.columns if c not in NON_FEATURE_COLS]
    X = df[feature_cols].copy()

    # Ensure numeric-only matrix for xgboost.
    for c in feature_cols:
        X[c] = pd.to_numeric(X[c], errors="coerce")
    X = X.fillna(0.0)

    return X, y, feature_cols


def compute_scale_pos_weight(y_train: pd.Series) -> float:
    pos = float((y_train == 1).sum())
    neg = float((y_train == 0).sum())
    if pos <= 0:
        return 1.0
    return max(1.0, neg / pos)


def evaluate_binary(y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.5) -> Dict[str, float]:
    y_pred = (y_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    out = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_prob)),
        "pr_auc": float(average_precision_score(y_true, y_prob)),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "fpr": float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0,
        "fnr": float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0,
    }
    return out


def save_gain_importance(model: xgb.XGBClassifier, feature_cols: List[str], out_csv: Path) -> None:
    booster = model.get_booster()
    gain_map = booster.get_score(importance_type="gain")
    rows = []
    for i, f in enumerate(feature_cols):
        key_fidx = f"f{i}"
        # XGBoost 2.x often uses f0/f1..., while 3.x may preserve original
        # column names. Support both to keep output stable across versions.
        gain = gain_map.get(f, gain_map.get(key_fidx, 0.0))
        rows.append({"feature": f, "gain": float(gain)})
    imp = pd.DataFrame(rows).sort_values("gain", ascending=False)
    imp.to_csv(out_csv, index=False)


def save_shap_artifacts(
    model: xgb.XGBClassifier,
    X_test: pd.DataFrame,
    feature_cols: List[str],
    out_dir: Path,
    shap_sample: int,
    shap_background: int,
) -> None:
    if len(X_test) > shap_sample:
        Xs = X_test.sample(n=shap_sample, random_state=42)
    else:
        Xs = X_test

    # Preferred path: TreeExplainer (fast, exact for tree models).
    # Fallback path: permutation SHAP for environments where current SHAP
    # version is incompatible with XGBoost model metadata format.
    shap_arr: np.ndarray
    try:
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(Xs)
        if isinstance(shap_values, list):
            # Binary classification could return a list in some SHAP versions.
            shap_arr = np.asarray(shap_values[-1])
        else:
            shap_arr = np.asarray(shap_values)
    except Exception:
        bg_n = min(max(16, shap_background), len(X_test))
        Xb = X_test.sample(n=bg_n, random_state=42) if len(X_test) > bg_n else X_test
        predictor = lambda arr: model.predict_proba(arr)[:, 1]
        explainer = shap.Explainer(predictor, Xb)
        explanation = explainer(Xs, silent=True)
        shap_arr = np.asarray(explanation.values)

    if shap_arr.ndim != 2:
        raise RuntimeError(f"unexpected SHAP shape: {shap_arr.shape}")

    mean_abs = np.mean(np.abs(shap_arr), axis=0)
    shap_df = pd.DataFrame({"feature": feature_cols, "mean_abs_shap": mean_abs})
    shap_df = shap_df.sort_values("mean_abs_shap", ascending=False)
    shap_df.to_csv(out_dir / "shap_mean_abs.csv", index=False)

    # SHAP summary plots.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=FutureWarning)
        plt.figure(figsize=(11, 6))
        shap.summary_plot(shap_arr, Xs, show=False, plot_type="dot")
        plt.tight_layout()
        plt.savefig(out_dir / "shap_beeswarm.png", dpi=180)
        plt.close()

        plt.figure(figsize=(11, 6))
        shap.summary_plot(shap_arr, Xs, show=False, plot_type="bar")
        plt.tight_layout()
        plt.savefig(out_dir / "shap_bar.png", dpi=180)
        plt.close()


def main() -> int:
    args = parse_args()

    data_path = Path(args.data).expanduser().resolve()
    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    X, y, feature_cols = load_dataset(data_path, args.positive_label)

    X_trainval, X_test, y_trainval, y_test = train_test_split(
        X,
        y,
        test_size=args.test_size,
        random_state=args.seed,
        stratify=y,
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_trainval,
        y_trainval,
        test_size=args.val_size,
        random_state=args.seed,
        stratify=y_trainval,
    )

    spw = compute_scale_pos_weight(y_train)

    model = xgb.XGBClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        learning_rate=args.learning_rate,
        subsample=args.subsample,
        colsample_bytree=args.colsample_bytree,
        min_child_weight=args.min_child_weight,
        objective="binary:logistic",
        eval_metric="logloss",
        tree_method="hist",
        n_jobs=-1,
        random_state=args.seed,
        scale_pos_weight=spw,
    )

    model.fit(
        X_train,
        y_train,
        eval_set=[(X_val, y_val)],
        verbose=False,
    )

    y_prob = model.predict_proba(X_test)[:, 1]
    metrics = evaluate_binary(y_test.to_numpy(), y_prob)

    metrics_payload = {
        "data": str(data_path),
        "out_dir": str(out_dir),
        "n_rows": int(len(X)),
        "n_features": int(len(feature_cols)),
        "positive_label": int(args.positive_label),
        "class_count": {
            "0": int((y == 0).sum()),
            "1": int((y == 1).sum()),
        },
        "split": {
            "train": int(len(X_train)),
            "val": int(len(X_val)),
            "test": int(len(X_test)),
        },
        "params": {
            "n_estimators": args.n_estimators,
            "max_depth": args.max_depth,
            "learning_rate": args.learning_rate,
            "subsample": args.subsample,
            "colsample_bytree": args.colsample_bytree,
            "min_child_weight": args.min_child_weight,
            "scale_pos_weight": spw,
            "seed": args.seed,
        },
        "metrics_test": metrics,
    }

    with (out_dir / "metrics.json").open("w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2, ensure_ascii=False)

    model.save_model(str(out_dir / "model_xgboost.json"))
    save_gain_importance(model, feature_cols, out_dir / "feature_importance_gain.csv")

    pred_df = X_test.copy()
    pred_df["y_true"] = y_test.to_numpy()
    pred_df["y_prob"] = y_prob
    pred_df["y_pred"] = (y_prob >= 0.5).astype(int)
    pred_df.to_csv(out_dir / "test_predictions.csv", index=False)

    save_shap_artifacts(
        model=model,
        X_test=X_test,
        feature_cols=feature_cols,
        out_dir=out_dir,
        shap_sample=args.shap_sample,
        shap_background=args.shap_background,
    )

    print("[ok] training complete")
    print(f"[ok] metrics      : {out_dir / 'metrics.json'}")
    print(f"[ok] model        : {out_dir / 'model_xgboost.json'}")
    print(f"[ok] shap summary : {out_dir / 'shap_mean_abs.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
