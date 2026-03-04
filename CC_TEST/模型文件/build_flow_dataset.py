#!/usr/bin/env python3
"""
Build a flow-level tabular dataset from packet-level CSV files.

Why flow-level:
- Packet-level labels are noisy for encrypted traffic detection tasks.
- Most recent encrypted-traffic IDS papers model per-flow statistics such as
  packet length distribution and inter-arrival-time (IAT) moments.

Input manifest format (JSON):
{
  "sources": [
    {"name": "baseline", "path": "CC_TEST/提取数据/out_benign", "label": 0},
    {"name": "covert",   "path": "CC_TEST/提取数据/out_covert", "label": 1}
  ]
}

Each source path can be:
- a directory containing packets_udp.csv
- a direct path to packets_udp.csv

Output:
- flow_dataset.csv: flow-level features + label
- flow_dataset_meta.json: provenance and class-balance summary
"""

from __future__ import annotations

import argparse
import json
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List

import numpy as np
import pandas as pd


REQUIRED_COLUMNS = [
    "ts_epoch",
    "iat_ms_global",
    "iat_ms_flow",
    "burst_id",
    "udp_len",
    "direction",
    "flow_key",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
]


@dataclass
class SourceItem:
    name: str
    label: int
    csv_path: Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build flow-level dataset from extracted packet CSVs.")
    parser.add_argument("--manifest", required=True, help="Path to dataset manifest JSON.")
    parser.add_argument("--out-csv", required=True, help="Output flow dataset CSV path.")
    parser.add_argument("--out-meta", required=True, help="Output metadata JSON path.")
    parser.add_argument(
        "--min-packets-per-flow",
        type=int,
        default=3,
        help="Drop flows with fewer packets than this threshold (default: 3).",
    )
    return parser.parse_args()


def resolve_csv(path_str: str) -> Path:
    p = Path(path_str).expanduser().resolve()
    if p.is_dir():
        p = p / "packets_udp.csv"
    if not p.exists():
        raise FileNotFoundError(f"packets csv not found: {p}")
    return p


def load_manifest(path: Path) -> List[SourceItem]:
    with path.open("r", encoding="utf-8") as f:
        obj = json.load(f)

    sources = obj.get("sources", [])
    if not isinstance(sources, list) or not sources:
        raise ValueError("manifest must contain non-empty 'sources' list")

    out: List[SourceItem] = []
    for idx, s in enumerate(sources, start=1):
        if not isinstance(s, dict):
            raise ValueError(f"manifest source #{idx} must be an object")
        if "path" not in s or "label" not in s:
            raise ValueError(f"manifest source #{idx} missing path/label")
        name = str(s.get("name") or f"source_{idx}")
        label = int(s["label"])
        csv_path = resolve_csv(str(s["path"]))
        out.append(SourceItem(name=name, label=label, csv_path=csv_path))
    return out


def safe_mean(arr: np.ndarray) -> float:
    return float(np.mean(arr)) if arr.size else 0.0


def safe_std(arr: np.ndarray) -> float:
    if arr.size <= 1:
        return 0.0
    return float(np.std(arr, ddof=1))


def q(arr: np.ndarray, ratio: float) -> float:
    if arr.size == 0:
        return 0.0
    return float(np.quantile(arr, ratio))


def ratio(n: float, d: float) -> float:
    if d <= 0:
        return 0.0
    return float(n / d)


def extract_flow_features(df: pd.DataFrame, source_name: str, source_label: int, min_packets: int) -> List[Dict[str, float]]:
    rows: List[Dict[str, float]] = []

    # Group by 5-tuple-derived stable key (already created by extractor).
    for flow_key, g in df.groupby("flow_key", sort=False):
        g = g.sort_values("ts_epoch")
        pkt_cnt = int(len(g))
        if pkt_cnt < min_packets:
            continue

        lengths = g["udp_len"].to_numpy(dtype=np.float64)
        iat_g = g["iat_ms_global"].to_numpy(dtype=np.float64)
        iat_f = g["iat_ms_flow"].to_numpy(dtype=np.float64)
        ts = g["ts_epoch"].to_numpy(dtype=np.float64)

        up_mask = (g["direction"].values == "uplink")
        down_mask = (g["direction"].values == "downlink")

        up_pkt = int(np.sum(up_mask))
        down_pkt = int(np.sum(down_mask))

        up_bytes = float(np.sum(lengths[up_mask])) if up_pkt > 0 else 0.0
        down_bytes = float(np.sum(lengths[down_mask])) if down_pkt > 0 else 0.0

        duration_ms = max(0.0, float((ts[-1] - ts[0]) * 1000.0))
        total_bytes = float(np.sum(lengths))

        burst_sizes = g.groupby("burst_id").size().to_numpy(dtype=np.float64)

        row: Dict[str, float] = {
            "label": int(source_label),
            "source_name": source_name,
            "flow_key": str(flow_key),
            "packet_count": pkt_cnt,
            "bytes_total": total_bytes,
            "duration_ms": duration_ms,
            "pps": ratio(pkt_cnt, duration_ms / 1000.0) if duration_ms > 0 else float(pkt_cnt),
            "bps": ratio(total_bytes, duration_ms / 1000.0) if duration_ms > 0 else total_bytes,
            "up_pkt_count": up_pkt,
            "down_pkt_count": down_pkt,
            "up_pkt_ratio": ratio(up_pkt, pkt_cnt),
            "down_pkt_ratio": ratio(down_pkt, pkt_cnt),
            "up_bytes": up_bytes,
            "down_bytes": down_bytes,
            "up_byte_ratio": ratio(up_bytes, total_bytes),
            "down_byte_ratio": ratio(down_bytes, total_bytes),
            "len_min": float(np.min(lengths)),
            "len_max": float(np.max(lengths)),
            "len_mean": safe_mean(lengths),
            "len_std": safe_std(lengths),
            "len_p50": q(lengths, 0.50),
            "len_p90": q(lengths, 0.90),
            "len_p99": q(lengths, 0.99),
            "iatg_mean": safe_mean(iat_g),
            "iatg_std": safe_std(iat_g),
            "iatg_p50": q(iat_g, 0.50),
            "iatg_p90": q(iat_g, 0.90),
            "iatg_p99": q(iat_g, 0.99),
            "iatg_max": float(np.max(iat_g)),
            "iatf_mean": safe_mean(iat_f),
            "iatf_std": safe_std(iat_f),
            "iatf_p50": q(iat_f, 0.50),
            "iatf_p90": q(iat_f, 0.90),
            "iatf_p99": q(iat_f, 0.99),
            "iatf_max": float(np.max(iat_f)),
            "burst_count": int(len(burst_sizes)),
            "burst_size_mean": safe_mean(burst_sizes),
            "burst_size_std": safe_std(burst_sizes),
            "burst_size_max": float(np.max(burst_sizes)) if burst_sizes.size else 0.0,
            "src_port_mode": float(g["src_port"].mode().iloc[0]),
            "dst_port_mode": float(g["dst_port"].mode().iloc[0]),
        }
        rows.append(row)

    return rows


def load_packets(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"{path} missing required columns: {missing}")
    # Defensive numeric conversion for robustness against malformed rows.
    for c in ["ts_epoch", "iat_ms_global", "iat_ms_flow", "udp_len", "src_port", "dst_port", "burst_id"]:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df = df.dropna(subset=["ts_epoch", "udp_len", "flow_key"])
    return df


def main() -> int:
    args = parse_args()

    manifest_path = Path(args.manifest).expanduser().resolve()
    out_csv = Path(args.out_csv).expanduser().resolve()
    out_meta = Path(args.out_meta).expanduser().resolve()

    if args.min_packets_per_flow <= 0:
        raise ValueError("--min-packets-per-flow must be > 0")

    sources = load_manifest(manifest_path)

    dataset_rows: List[Dict[str, float]] = []
    source_stats: List[Dict[str, object]] = []

    for src in sources:
        df = load_packets(src.csv_path)
        rows = extract_flow_features(df, src.name, src.label, args.min_packets_per_flow)
        dataset_rows.extend(rows)
        source_stats.append(
            {
                "name": src.name,
                "label": src.label,
                "csv_path": str(src.csv_path),
                "packet_rows": int(len(df)),
                "flow_rows": int(len(rows)),
                "flow_key_unique": int(df["flow_key"].nunique()),
            }
        )

    if not dataset_rows:
        raise RuntimeError("no flow rows generated, please check manifest and min-packets threshold")

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    out_meta.parent.mkdir(parents=True, exist_ok=True)

    dataset = pd.DataFrame(dataset_rows)
    dataset = dataset.sort_values(["label", "source_name", "flow_key"]).reset_index(drop=True)
    dataset.to_csv(out_csv, index=False)

    class_counts = dataset["label"].value_counts().sort_index().to_dict()
    meta = {
        "manifest": str(manifest_path),
        "out_csv": str(out_csv),
        "row_count": int(len(dataset)),
        "feature_count_total_columns": int(len(dataset.columns)),
        "class_counts": {str(k): int(v) for k, v in class_counts.items()},
        "source_stats": source_stats,
        "min_packets_per_flow": int(args.min_packets_per_flow),
    }
    with out_meta.open("w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    print(f"[ok] flow dataset saved: {out_csv}")
    print(f"[ok] metadata saved    : {out_meta}")
    print(f"[ok] rows={len(dataset)}, classes={meta['class_counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
