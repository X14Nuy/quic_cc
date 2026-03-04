#!/usr/bin/env python3
"""
PCAP feature extraction utility for QUIC-over-UDP traffic.

Design goals:
1) Keep dependency footprint minimal (only Python stdlib + tcpdump binary).
2) Export packet-level timeline features used by Module A / modeling stage.
3) Build discrete PDFs for packet length and inter-arrival time (IAT), so the
   output can be directly consumed by Alias sampling or ML pipelines.

Outputs:
- packets_udp.csv      : packet-level features
- pdf_len.csv          : packet length histogram + PDF (0..len_max)
- pdf_iat_ms.csv       : IAT histogram + PDF (0..max_iat_ms)
- summary.json         : dataset statistics and quality indicators
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import statistics
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


UDP_LINE_RE = re.compile(
    r"^(?P<ts>\d+\.\d+)\s+"
    r"(?:(?P<iface>\S+)\s+(?:In|Out)\s+)?"
    r"IP6?\s+"
    r"(?P<src>\S+)\s+>\s+(?P<dst>\S+):\s+UDP,\s+length\s+(?P<len>\d+)"
)


@dataclass
class PacketFeature:
    index: int
    ts_epoch: float
    iat_ms_global: float
    iat_ms_flow: float
    burst_id: int
    udp_len: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    direction: str
    flow_key: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract QUIC/UDP statistical features from a pcap file."
    )
    parser.add_argument(
        "--pcap",
        required=True,
        help="Input pcap file path (captured by Wireshark/tcpdump).",
    )
    parser.add_argument(
        "--out-dir",
        default="",
        help="Output directory. Default: CC_TEST/提取数据/out_<timestamp>.",
    )
    parser.add_argument(
        "--server-port",
        type=int,
        default=4433,
        help="QUIC server UDP port used to infer uplink/downlink direction.",
    )
    parser.add_argument(
        "--bpf",
        default="",
        help="tcpdump read filter. Default: 'udp and port <server-port>'.",
    )
    parser.add_argument(
        "--len-max",
        type=int,
        default=1500,
        help="Packet length histogram max bin (default: 1500).",
    )
    parser.add_argument(
        "--max-iat-ms",
        type=int,
        default=5000,
        help="IAT histogram max bin in ms (default: 5000).",
    )
    parser.add_argument(
        "--burst-gap-ms",
        type=float,
        default=20.0,
        help="Global IAT threshold to start a new burst (default: 20ms).",
    )
    parser.add_argument(
        "--tcpdump-bin",
        default="tcpdump",
        help="tcpdump executable path/name (default: tcpdump).",
    )
    return parser.parse_args()


def run_cmd(cmd: List[str]) -> str:
    try:
        completed = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"command not found: {cmd[0]}") from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        raise RuntimeError(
            f"command failed ({' '.join(cmd)}): {stderr if stderr else exc}"
        ) from exc
    return completed.stdout


def endpoint_split(endpoint: str) -> Tuple[str, int]:
    """
    Split endpoint in form '<ip>.<port>' used by tcpdump textual output.
    Works for:
    - IPv4: 127.0.0.1.4433
    - IPv6: ::1.4433
    """
    if "." not in endpoint:
        raise ValueError(f"malformed endpoint (no port separator): {endpoint}")
    ip_part, port_part = endpoint.rsplit(".", 1)
    if not port_part.isdigit():
        raise ValueError(f"malformed endpoint port: {endpoint}")
    return ip_part, int(port_part)


def infer_direction(src_port: int, dst_port: int, server_port: int) -> str:
    if src_port == server_port and dst_port != server_port:
        return "downlink"
    if dst_port == server_port and src_port != server_port:
        return "uplink"
    if src_port == server_port and dst_port == server_port:
        return "server_loop"
    return "unknown"


def infer_flow_key(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int, server_port: int
) -> str:
    """
    Build a stable flow key anchored by the server port if possible.
    """
    if src_port == server_port and dst_port != server_port:
        peer_ip, peer_port = dst_ip, dst_port
    elif dst_port == server_port and src_port != server_port:
        peer_ip, peer_port = src_ip, src_port
    else:
        # Fallback: canonicalize 4-tuple ordering for deterministic grouping.
        left = f"{src_ip}:{src_port}"
        right = f"{dst_ip}:{dst_port}"
        if left <= right:
            return f"{left}<->{right}"
        return f"{right}<->{left}"
    return f"{peer_ip}:{peer_port}<->server:{server_port}"


def parse_udp_packets(
    tcpdump_bin: str,
    pcap_path: str,
    bpf: str,
    server_port: int,
    burst_gap_ms: float,
) -> List[PacketFeature]:
    cmd = [tcpdump_bin, "-nn", "-tt", "-r", pcap_path]
    if bpf:
        cmd.append(bpf)

    output = run_cmd(cmd)
    packets: List[PacketFeature] = []
    prev_ts: Optional[float] = None
    flow_last_ts: Dict[str, float] = {}
    burst_id = 0

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        m = UDP_LINE_RE.match(line)
        if not m:
            continue

        ts_epoch = float(m.group("ts"))
        udp_len = int(m.group("len"))

        try:
            src_ip, src_port = endpoint_split(m.group("src"))
            dst_ip, dst_port = endpoint_split(m.group("dst"))
        except ValueError:
            # Ignore unparsable endpoints to keep extractor robust.
            continue

        direction = infer_direction(src_port, dst_port, server_port)
        flow_key = infer_flow_key(src_ip, src_port, dst_ip, dst_port, server_port)

        if prev_ts is None:
            iat_global = 0.0
        else:
            iat_global = max(0.0, (ts_epoch - prev_ts) * 1000.0)
            if iat_global > burst_gap_ms:
                burst_id += 1
        prev_ts = ts_epoch

        prev_flow_ts = flow_last_ts.get(flow_key)
        if prev_flow_ts is None:
            iat_flow = 0.0
        else:
            iat_flow = max(0.0, (ts_epoch - prev_flow_ts) * 1000.0)
        flow_last_ts[flow_key] = ts_epoch

        packets.append(
            PacketFeature(
                index=len(packets) + 1,
                ts_epoch=ts_epoch,
                iat_ms_global=iat_global,
                iat_ms_flow=iat_flow,
                burst_id=burst_id,
                udp_len=udp_len,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                direction=direction,
                flow_key=flow_key,
            )
        )

    return packets


def write_packet_csv(path: Path, packets: Iterable[PacketFeature]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "index",
                "ts_epoch",
                "iat_ms_global",
                "iat_ms_flow",
                "burst_id",
                "udp_len",
                "src_ip",
                "src_port",
                "dst_ip",
                "dst_port",
                "direction",
                "flow_key",
            ]
        )
        for p in packets:
            writer.writerow(
                [
                    p.index,
                    f"{p.ts_epoch:.6f}",
                    f"{p.iat_ms_global:.6f}",
                    f"{p.iat_ms_flow:.6f}",
                    p.burst_id,
                    p.udp_len,
                    p.src_ip,
                    p.src_port,
                    p.dst_ip,
                    p.dst_port,
                    p.direction,
                    p.flow_key,
                ]
            )


def build_pdf(values: List[float], max_bin: int) -> Tuple[List[int], List[float], int]:
    """
    Build discrete histogram and PDF with truncation to [0, max_bin].
    Returns (counts, pdf, overflow_count).
    """
    counts = [0] * (max_bin + 1)
    overflow = 0

    for v in values:
        if v < 0:
            b = 0
        else:
            b = int(v)
        if b > max_bin:
            overflow += 1
            b = max_bin
        counts[b] += 1

    total = sum(counts)
    if total == 0:
        pdf = [0.0] * len(counts)
    else:
        pdf = [c / total for c in counts]

    return counts, pdf, overflow


def write_pdf_csv(path: Path, counts: List[int], pdf: List[float]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["bin", "count", "pdf"])
        for i, (c, p) in enumerate(zip(counts, pdf)):
            writer.writerow([i, c, f"{p:.10f}"])


def get_icmp_count(tcpdump_bin: str, pcap_path: str) -> int:
    cmd = [tcpdump_bin, "-nn", "-tt", "-r", pcap_path, "icmp or icmp6"]
    output = run_cmd(cmd)
    # tcpdump stdout can include non-packet lines in edge cases, so count only
    # lines starting with timestamp.
    count = 0
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if re.match(r"^\d+\.\d+", line):
            count += 1
    return count


def percentile(values: List[float], ratio: float) -> float:
    if not values:
        return 0.0
    if ratio <= 0:
        return min(values)
    if ratio >= 1:
        return max(values)
    sorted_vals = sorted(values)
    idx = int(ratio * (len(sorted_vals) - 1))
    return sorted_vals[idx]


def main() -> int:
    args = parse_args()

    pcap_path = os.path.abspath(args.pcap)
    if not os.path.exists(pcap_path):
        print(f"[error] pcap not found: {pcap_path}", file=sys.stderr)
        return 1

    if args.len_max <= 0:
        print("[error] --len-max must be > 0", file=sys.stderr)
        return 1
    if args.max_iat_ms <= 0:
        print("[error] --max-iat-ms must be > 0", file=sys.stderr)
        return 1
    if args.server_port <= 0 or args.server_port > 65535:
        print("[error] --server-port out of range", file=sys.stderr)
        return 1

    out_dir = args.out_dir.strip()
    if not out_dir:
        ts = time.strftime("%Y%m%d_%H%M%S")
        out_dir = os.path.join(
            os.path.dirname(__file__),
            f"out_{ts}",
        )
    out_path = Path(out_dir).resolve()
    out_path.mkdir(parents=True, exist_ok=True)

    bpf = args.bpf.strip() if args.bpf.strip() else f"udp and port {args.server_port}"

    try:
        packets = parse_udp_packets(
            tcpdump_bin=args.tcpdump_bin,
            pcap_path=pcap_path,
            bpf=bpf,
            server_port=args.server_port,
            burst_gap_ms=args.burst_gap_ms,
        )
    except RuntimeError as exc:
        print(f"[error] parse failed: {exc}", file=sys.stderr)
        return 2

    if not packets:
        print("[error] no UDP packets parsed. Check --bpf / pcap content.", file=sys.stderr)
        return 3

    packet_csv = out_path / "packets_udp.csv"
    write_packet_csv(packet_csv, packets)

    lengths = [float(p.udp_len) for p in packets]
    iats = [p.iat_ms_global for p in packets]
    iats_flow = [p.iat_ms_flow for p in packets]

    len_counts, len_pdf, len_overflow = build_pdf(lengths, args.len_max)
    iat_counts, iat_pdf, iat_overflow = build_pdf(iats, args.max_iat_ms)

    len_pdf_csv = out_path / "pdf_len.csv"
    iat_pdf_csv = out_path / "pdf_iat_ms.csv"
    write_pdf_csv(len_pdf_csv, len_counts, len_pdf)
    write_pdf_csv(iat_pdf_csv, iat_counts, iat_pdf)

    direction_counter = Counter(p.direction for p in packets)
    flow_counter = Counter(p.flow_key for p in packets)

    try:
        icmp_count = get_icmp_count(args.tcpdump_bin, pcap_path)
    except RuntimeError:
        icmp_count = -1

    start_ts = packets[0].ts_epoch
    end_ts = packets[-1].ts_epoch
    duration = max(0.0, end_ts - start_ts)

    summary = {
        "input_pcap": pcap_path,
        "filter_bpf": bpf,
        "output_dir": str(out_path),
        "packet_count_udp": len(packets),
        "packet_count_icmp": icmp_count,
        "duration_sec": round(duration, 6),
        "start_ts_epoch": round(start_ts, 6),
        "end_ts_epoch": round(end_ts, 6),
        "rate_pps": round((len(packets) / duration) if duration > 0 else 0.0, 6),
        "direction_count": dict(direction_counter),
        "flow_count": len(flow_counter),
        "top_flows": flow_counter.most_common(20),
        "len_stat": {
            "min": int(min(lengths)),
            "max": int(max(lengths)),
            "mean": round(statistics.fmean(lengths), 6),
            "p50": round(percentile(lengths, 0.50), 6),
            "p90": round(percentile(lengths, 0.90), 6),
            "p99": round(percentile(lengths, 0.99), 6),
            "hist_truncated_to_bin": args.len_max,
            "overflow_count": len_overflow,
        },
        "iat_global_ms_stat": {
            "min": round(min(iats), 6),
            "max": round(max(iats), 6),
            "mean": round(statistics.fmean(iats), 6),
            "p50": round(percentile(iats, 0.50), 6),
            "p90": round(percentile(iats, 0.90), 6),
            "p99": round(percentile(iats, 0.99), 6),
            "hist_truncated_to_bin": args.max_iat_ms,
            "overflow_count": iat_overflow,
        },
        "iat_flow_ms_stat": {
            "min": round(min(iats_flow), 6),
            "max": round(max(iats_flow), 6),
            "mean": round(statistics.fmean(iats_flow), 6),
            "p50": round(percentile(iats_flow, 0.50), 6),
            "p90": round(percentile(iats_flow, 0.90), 6),
            "p99": round(percentile(iats_flow, 0.99), 6),
        },
        "quality_notes": [
            "Loopback captures (127.0.0.1/::1) are useful for functional testing, but not ideal for realism.",
            "Use a dedicated NIC and cross-host deployment for final stealth evaluation.",
            "Prefer filtering by UDP server port to reduce unrelated traffic leakage.",
        ],
    }

    summary_json = out_path / "summary.json"
    with summary_json.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print("[ok] extraction completed")
    print(f"[ok] packet csv : {packet_csv}")
    print(f"[ok] len pdf    : {len_pdf_csv}")
    print(f"[ok] iat pdf    : {iat_pdf_csv}")
    print(f"[ok] summary    : {summary_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
