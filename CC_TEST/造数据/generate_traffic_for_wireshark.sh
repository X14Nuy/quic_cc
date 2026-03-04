#!/usr/bin/env bash
set -Eeuo pipefail

# -----------------------------------------------------------------------------
# Traffic generation + tcpdump auto-capture helper.
# One-click workflow:
# 1) start tcpdump capture
# 2) run server + clients and generate QUIC traffic
# 3) stop tcpdump and keep pcap for later feature extraction
# -----------------------------------------------------------------------------

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build"
SERVER_BIN="${BUILD_DIR}/quic_secure_server"
CLIENT_BIN="${BUILD_DIR}/quic_secure_client"
LOG_DIR="${PROJECT_ROOT}/CC_TEST/日志"
CAPTURE_DIR="${PROJECT_ROOT}/CC_TEST/抓包文件"

HOST="127.0.0.1"
PORT="4433"
CLIENTS="10"
ROUNDS="60"
ENTROPY_LEN="120"
UNIT_SEC="1"
START_GAP_SEC="0.2"
FRAG_RETRIES="3"
ENABLE_SERVER_PUSH="0"
PUSH_COUNT="60"
PUSH_MIN_INTERVAL="1"
PUSH_MAX_INTERVAL="3"
KEY=""
START_LOCAL_SERVER="auto"
PRECHECK_REMOTE="1"
PRECHECK_ENTROPY_LEN="96"
CAPTURE_IFACE="auto"
CAPTURE_FILTER=""
CAPTURE_FILE=""
CAPTURE_SNAPLEN="262144"
CAPTURE_TS_PRECISION="nano"
CAPTURE_USE_SUDO="auto"

SERVER_PID=""
PUSH_PID=""
TCPDUMP_PID=""
CLIENT_PIDS=()
CLIENT_OK_COUNT=0
CLIENT_FAIL_COUNT=0
FIFO_PATH=""
FIFO_FD_OPENED="0"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options]

Options:
  --host <ip_or_name>           Server host for clients (default: ${HOST})
  --port <udp_port>             Server UDP port (default: ${PORT})
  --key <64hex>                 Shared key. If omitted, random key is generated.
  --clients <N>                 Parallel client processes (default: ${CLIENTS})
  --rounds <N>                  Rounds per client, 0 means infinite (default: ${ROUNDS})
  --entropy-len <bytes>         High-entropy payload bytes per round (default: ${ENTROPY_LEN})
  --frag-retries <N>            Retries per CID fragment at client side (default: ${FRAG_RETRIES})
  --unit-sec <sec>              Unit for (UTC%60)*unit schedule (default: ${UNIT_SEC})
  --start-gap <sec>             Delay between launching clients (default: ${START_GAP_SEC})
  --server-push <0|1>           Enable server->client push loop (default: ${ENABLE_SERVER_PUSH})
  --push-count <N>              Number of push commands when enabled (default: ${PUSH_COUNT})
  --push-min-interval <sec>     Min sleep between push commands (default: ${PUSH_MIN_INTERVAL})
  --push-max-interval <sec>     Max sleep between push commands (default: ${PUSH_MAX_INTERVAL})
  --start-local-server <auto|0|1> local server mode (default: ${START_LOCAL_SERVER})
  --precheck-remote <0|1>       run one-shot remote health check before capture (default: ${PRECHECK_REMOTE})
  --precheck-entropy-len <bytes> entropy bytes used in remote precheck (default: ${PRECHECK_ENTROPY_LEN})
  --capture-iface <name|auto>   tcpdump interface (default: ${CAPTURE_IFACE})
  --capture-filter <bpf>        tcpdump BPF filter (default: udp and port <port>)
  --capture-file <path>         output pcap file path (default: CC_TEST/抓包文件/*.pcap)
  --snaplen <N>                 tcpdump snapshot length (default: ${CAPTURE_SNAPLEN})
  --ts-precision <micro|nano>   tcpdump timestamp precision (default: ${CAPTURE_TS_PRECISION})
  --capture-use-sudo <auto|0|1> run tcpdump via sudo:
                               auto=try direct then sudo -n,
                               0=no sudo,
                               1=sudo with password prompt if needed
  -h, --help                    Show this help

Example:
  $(basename "$0") --clients 20 --rounds 120 --entropy-len 120 --frag-retries 5 --unit-sec 1
  $(basename "$0") --host 43.99.6.2 --start-local-server 0 --precheck-remote 1 --capture-use-sudo 1
  $(basename "$0") --capture-iface lo --capture-filter "udp and port 4433"
USAGE
}

random_hex() {
  local nbytes="$1"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "${nbytes}"
  else
    # fallback, less strong but sufficient for test label text
    printf "%08x%08x%08x\n" "$RANDOM" "$RANDOM" "$(date +%s)"
  fi
}

normalize_capture_iface() {
  local host_lc

  host_lc="$(printf '%s' "${HOST}" | tr '[:upper:]' '[:lower:]')"

  if [[ "${CAPTURE_IFACE}" != "auto" ]]; then
    printf '%s\n' "${CAPTURE_IFACE}"
    return
  fi

  if [[ "${host_lc}" == "127.0.0.1" || "${host_lc}" == "localhost" || "${host_lc}" == "::1" ]]; then
    printf 'lo\n'
  else
    printf 'any\n'
  fi
}

is_local_host() {
  local host_lc
  host_lc="$(printf '%s' "${HOST}" | tr '[:upper:]' '[:lower:]')"
  [[ "${host_lc}" == "127.0.0.1" || "${host_lc}" == "localhost" || "${host_lc}" == "::1" ]]
}

resolve_local_server_mode() {
  if [[ "${START_LOCAL_SERVER}" == "auto" ]]; then
    if is_local_host; then
      printf '1\n'
    else
      printf '0\n'
    fi
    return 0
  fi

  if [[ "${START_LOCAL_SERVER}" == "0" || "${START_LOCAL_SERVER}" == "1" ]]; then
    printf '%s\n' "${START_LOCAL_SERVER}"
    return 0
  fi

  echo "[error] invalid --start-local-server: ${START_LOCAL_SERVER} (must be auto|0|1)" >&2
  return 1
}

supports_ts_precision() {
  if tcpdump --help 2>&1 | grep -q -- "--time-stamp-precision"; then
    return 0
  fi
  return 1
}

launch_tcpdump_once() {
  local sudo_mode="$1"
  local iface="$2"
  local filter="$3"
  local pcap_out="$4"
  local ts_precision="$5"
  local log_file="$6"
  local -a cmd

  cmd=(tcpdump -U -n -i "${iface}" -s "${CAPTURE_SNAPLEN}" -w "${pcap_out}")

  if supports_ts_precision; then
    cmd+=(--time-stamp-precision "${ts_precision}")
  fi

  if [[ -n "${filter}" ]]; then
    cmd+=("${filter}")
  fi

  if [[ "${sudo_mode}" == "1" ]]; then
    if ! command -v sudo >/dev/null 2>&1; then
      return 11
    fi
    sudo -n "${cmd[@]}" > "${log_file}" 2>&1 &
  elif [[ "${sudo_mode}" == "prompt" ]]; then
    if ! command -v sudo >/dev/null 2>&1; then
      return 11
    fi
    sudo "${cmd[@]}" > "${log_file}" 2>&1 &
  else
    "${cmd[@]}" > "${log_file}" 2>&1 &
  fi

  TCPDUMP_PID="$!"
  sleep 1

  if ! kill -0 "${TCPDUMP_PID}" 2>/dev/null; then
    wait "${TCPDUMP_PID}" 2>/dev/null || true
    TCPDUMP_PID=""
    return 12
  fi

  return 0
}

start_capture() {
  local iface="$1"
  local filter="$2"
  local pcap_out="$3"
  local ts_precision="$4"
  local log_file="${LOG_DIR}/tcpdump_${RUN_ID}.log"
  local rc=0

  if ! command -v tcpdump >/dev/null 2>&1; then
    echo "[error] tcpdump not found. Please install tcpdump first." >&2
    return 1
  fi

  mkdir -p "${CAPTURE_DIR}"

  if supports_ts_precision; then
    if [[ "${ts_precision}" != "micro" && "${ts_precision}" != "nano" ]]; then
      echo "[error] invalid --ts-precision: ${ts_precision} (must be micro|nano)" >&2
      return 1
    fi
  else
    echo "[warn] tcpdump does not support --time-stamp-precision; fallback to default precision."
  fi

  if [[ "${CAPTURE_USE_SUDO}" == "auto" ]]; then
    if launch_tcpdump_once "0" "${iface}" "${filter}" "${pcap_out}" "${ts_precision}" "${log_file}"; then
      return 0
    fi
    rc=$?
    if [[ "${rc}" -eq 12 ]] && grep -qiE "permission|operation not permitted|you don't have permission" "${log_file}" 2>/dev/null; then
      if launch_tcpdump_once "1" "${iface}" "${filter}" "${pcap_out}" "${ts_precision}" "${log_file}"; then
        return 0
      fi
    fi
  elif [[ "${CAPTURE_USE_SUDO}" == "1" ]]; then
    if launch_tcpdump_once "prompt" "${iface}" "${filter}" "${pcap_out}" "${ts_precision}" "${log_file}"; then
      return 0
    fi
  elif [[ "${CAPTURE_USE_SUDO}" == "0" ]]; then
    if launch_tcpdump_once "0" "${iface}" "${filter}" "${pcap_out}" "${ts_precision}" "${log_file}"; then
      return 0
    fi
  else
    echo "[error] invalid --capture-use-sudo: ${CAPTURE_USE_SUDO} (must be auto|0|1)" >&2
    return 1
  fi

  echo "[error] failed to start tcpdump. Check permissions and interface name." >&2
  echo "[error] tcpdump log: ${log_file}" >&2
  echo "[hint] try: sudo ./CC_TEST/造数据/$(basename "$0") ..." >&2
  return 1
}

stop_capture() {
  if [[ -n "${TCPDUMP_PID}" ]] && kill -0 "${TCPDUMP_PID}" 2>/dev/null; then
    kill -INT "${TCPDUMP_PID}" 2>/dev/null || true
    wait "${TCPDUMP_PID}" 2>/dev/null || true
    TCPDUMP_PID=""
  fi
}

run_remote_precheck() {
  local precheck_log="$1"

  echo "[info] remote precheck started, host=${HOST}:${PORT}"

  if command -v timeout >/dev/null 2>&1; then
    if timeout 25 "${CLIENT_BIN}" \
      -s "${HOST}" \
      -p "${PORT}" \
      -k "${KEY}" \
      -u 1 \
      -r 1 \
      -e "${PRECHECK_ENTROPY_LEN}" \
      -R "${FRAG_RETRIES}" \
      > "${precheck_log}" 2>&1; then
      echo "[info] remote precheck passed"
      return 0
    fi
  else
    if "${CLIENT_BIN}" \
      -s "${HOST}" \
      -p "${PORT}" \
      -k "${KEY}" \
      -u 1 \
      -r 1 \
      -e "${PRECHECK_ENTROPY_LEN}" \
      -R "${FRAG_RETRIES}" \
      > "${precheck_log}" 2>&1; then
      echo "[info] remote precheck passed"
      return 0
    fi
  fi

  echo "[error] remote precheck failed. server may be unreachable or key mismatch." >&2
  echo "[error] precheck log: ${precheck_log}" >&2
  tail -n 40 "${precheck_log}" 2>/dev/null || true
  return 1
}

cleanup() {
  local pid

  set +e

  stop_capture

  if [[ -n "${PUSH_PID}" ]] && kill -0 "${PUSH_PID}" 2>/dev/null; then
    kill -TERM "${PUSH_PID}" 2>/dev/null || true
    wait "${PUSH_PID}" 2>/dev/null || true
  fi

  for pid in "${CLIENT_PIDS[@]:-}"; do
    if kill -0 "${pid}" 2>/dev/null; then
      kill -TERM "${pid}" 2>/dev/null || true
    fi
  done

  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill -INT "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi

  if [[ "${FIFO_FD_OPENED}" == "1" ]]; then
    exec 3>&-
  fi
  if [[ -n "${FIFO_PATH}" ]]; then
    rm -f "${FIFO_PATH}" 2>/dev/null || true
  fi
}

trap cleanup EXIT INT TERM

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --key) KEY="$2"; shift 2 ;;
    --clients) CLIENTS="$2"; shift 2 ;;
    --rounds) ROUNDS="$2"; shift 2 ;;
    --entropy-len) ENTROPY_LEN="$2"; shift 2 ;;
    --frag-retries) FRAG_RETRIES="$2"; shift 2 ;;
    --unit-sec) UNIT_SEC="$2"; shift 2 ;;
    --start-gap) START_GAP_SEC="$2"; shift 2 ;;
    --server-push) ENABLE_SERVER_PUSH="$2"; shift 2 ;;
    --push-count) PUSH_COUNT="$2"; shift 2 ;;
    --push-min-interval) PUSH_MIN_INTERVAL="$2"; shift 2 ;;
    --push-max-interval) PUSH_MAX_INTERVAL="$2"; shift 2 ;;
    --start-local-server) START_LOCAL_SERVER="$2"; shift 2 ;;
    --precheck-remote) PRECHECK_REMOTE="$2"; shift 2 ;;
    --precheck-entropy-len) PRECHECK_ENTROPY_LEN="$2"; shift 2 ;;
    --capture-iface) CAPTURE_IFACE="$2"; shift 2 ;;
    --capture-filter) CAPTURE_FILTER="$2"; shift 2 ;;
    --capture-file) CAPTURE_FILE="$2"; shift 2 ;;
    --snaplen) CAPTURE_SNAPLEN="$2"; shift 2 ;;
    --ts-precision) CAPTURE_TS_PRECISION="$2"; shift 2 ;;
    --capture-use-sudo) CAPTURE_USE_SUDO="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "[error] Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ ! -x "${SERVER_BIN}" || ! -x "${CLIENT_BIN}" ]]; then
  echo "[error] Missing binaries in ${BUILD_DIR}. Build first:" >&2
  echo "        cmake -S . -B build && cmake --build build -j4" >&2
  exit 1
fi

if [[ -z "${KEY}" ]]; then
  KEY="$(random_hex 32)"
fi
if [[ "${PRECHECK_REMOTE}" != "0" && "${PRECHECK_REMOTE}" != "1" ]]; then
  echo "[error] invalid --precheck-remote: ${PRECHECK_REMOTE} (must be 0|1)" >&2
  exit 1
fi
if ! [[ "${FRAG_RETRIES}" =~ ^[0-9]+$ ]]; then
  echo "[error] invalid --frag-retries: ${FRAG_RETRIES} (must be integer >=0)" >&2
  exit 1
fi
if ! [[ "${PRECHECK_ENTROPY_LEN}" =~ ^[0-9]+$ ]] || [[ "${PRECHECK_ENTROPY_LEN}" -eq 0 ]]; then
  echo "[error] invalid --precheck-entropy-len: ${PRECHECK_ENTROPY_LEN} (must be integer >0)" >&2
  exit 1
fi

mkdir -p "${LOG_DIR}"
mkdir -p "${CAPTURE_DIR}"
RUN_ID="$(date +%Y%m%d_%H%M%S)"
SERVER_LOG="${LOG_DIR}/server_${RUN_ID}.log"
PRECHECK_LOG="${LOG_DIR}/precheck_${RUN_ID}.log"
if [[ -n "${CAPTURE_FILE}" ]]; then
  PCAP_OUT="${CAPTURE_FILE}"
else
  PCAP_OUT="${CAPTURE_DIR}/quic_traffic_${RUN_ID}.pcap"
fi
if [[ -z "${CAPTURE_FILTER}" ]]; then
  CAPTURE_FILTER="udp and port ${PORT}"
fi
EFFECTIVE_IFACE="$(normalize_capture_iface)"
EFFECTIVE_START_LOCAL_SERVER="$(resolve_local_server_mode)"

if [[ "${EFFECTIVE_START_LOCAL_SERVER}" == "0" && "${ENABLE_SERVER_PUSH}" == "1" ]]; then
  echo "[warn] --server-push requires local server mode; forcing --server-push 0"
  ENABLE_SERVER_PUSH="0"
fi

if [[ "${EFFECTIVE_START_LOCAL_SERVER}" == "0" && "${PRECHECK_REMOTE}" == "1" ]]; then
  run_remote_precheck "${PRECHECK_LOG}"
fi

if start_capture "${EFFECTIVE_IFACE}" "${CAPTURE_FILTER}" "${PCAP_OUT}" "${CAPTURE_TS_PRECISION}"; then
  :
else
  exit 1
fi

if [[ "${EFFECTIVE_START_LOCAL_SERVER}" == "1" ]]; then
  FIFO_PATH="/tmp/qsc_cmd_${RUN_ID}.fifo"
  rm -f "${FIFO_PATH}"
  mkfifo "${FIFO_PATH}"

  # Start server with command FIFO as stdin.
  "${SERVER_BIN}" -p "${PORT}" -k "${KEY}" < "${FIFO_PATH}" > "${SERVER_LOG}" 2>&1 &
  SERVER_PID="$!"

  # Keep a write endpoint open for runtime commands.
  exec 3>"${FIFO_PATH}"
  FIFO_FD_OPENED="1"

  sleep 1
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "[error] local server failed to start, check log: ${SERVER_LOG}" >&2
    tail -n 40 "${SERVER_LOG}" 2>/dev/null || true
    exit 1
  fi
fi

echo "[info] ------------------------------------------------------------------"
echo "[info] Traffic generator started"
echo "[info] mode=$([[ "${EFFECTIVE_START_LOCAL_SERVER}" == "1" ]] && echo "local-server" || echo "remote-server")"
echo "[info] key=${KEY}"
if [[ "${EFFECTIVE_START_LOCAL_SERVER}" == "1" ]]; then
  echo "[info] server_log=${SERVER_LOG}"
else
  echo "[info] remote_precheck_log=${PRECHECK_LOG}"
fi
echo "[info] tcpdump_log=${LOG_DIR}/tcpdump_${RUN_ID}.log"
echo "[info] clients=${CLIENTS}, rounds=${ROUNDS}, entropy_len=${ENTROPY_LEN}, unit_sec=${UNIT_SEC}"
echo "[info] frag_retries=${FRAG_RETRIES}, precheck_entropy_len=${PRECHECK_ENTROPY_LEN}"
echo "[info] capture_iface=${EFFECTIVE_IFACE}"
echo "[info] capture_filter=${CAPTURE_FILTER}"
echo "[info] capture_file=${PCAP_OUT}"
if [[ "${HOST}" == "127.0.0.1" || "${HOST}" == "localhost" ]]; then
  echo "[warn] host=${HOST} means loopback traffic only; timing/IP distribution is less realistic."
  echo "[warn] For research dataset quality, prefer cross-host capture on real NIC."
fi
echo "[info] ------------------------------------------------------------------"

# Optional server push loop to produce reverse-direction traffic.
if [[ "${ENABLE_SERVER_PUSH}" == "1" ]]; then
  (
    i=1
    while [[ "${i}" -le "${PUSH_COUNT}" ]]; do
      msg="srv_push_${RUN_ID}_${i}_$(random_hex 8)"
      echo "send all ${msg}" >&3 || true

      # random sleep in [min, max]
      if [[ "${PUSH_MAX_INTERVAL}" -lt "${PUSH_MIN_INTERVAL}" ]]; then
        sleep "${PUSH_MIN_INTERVAL}"
      else
        span=$((PUSH_MAX_INTERVAL - PUSH_MIN_INTERVAL + 1))
        delay=$((PUSH_MIN_INTERVAL + (RANDOM % span)))
        sleep "${delay}"
      fi
      i=$((i + 1))
    done
  ) &
  PUSH_PID="$!"
fi

# Start clients.
for i in $(seq 1 "${CLIENTS}"); do
  client_log="${LOG_DIR}/client_${RUN_ID}_${i}.log"
  "${CLIENT_BIN}" \
    -s "${HOST}" \
    -p "${PORT}" \
    -k "${KEY}" \
    -u "${UNIT_SEC}" \
    -r "${ROUNDS}" \
    -e "${ENTROPY_LEN}" \
    -R "${FRAG_RETRIES}" \
    > "${client_log}" 2>&1 &

  CLIENT_PIDS+=("$!")
  sleep "${START_GAP_SEC}"
done

# Wait clients to finish.
for pid in "${CLIENT_PIDS[@]}"; do
  if wait "${pid}"; then
    CLIENT_OK_COUNT=$((CLIENT_OK_COUNT + 1))
  else
    CLIENT_FAIL_COUNT=$((CLIENT_FAIL_COUNT + 1))
  fi
done

# Stop server push loop right after clients end, to avoid pushing to expired
# client ports that may generate ICMP unreachable noise.
if [[ -n "${PUSH_PID}" ]] && kill -0 "${PUSH_PID}" 2>/dev/null; then
  kill -TERM "${PUSH_PID}" 2>/dev/null || true
  wait "${PUSH_PID}" 2>/dev/null || true
  PUSH_PID=""
fi

# Wait push loop if enabled.
if [[ -n "${PUSH_PID}" ]]; then
  wait "${PUSH_PID}" || true
fi

echo "[info] All client processes completed."
echo "[info] client_ok=${CLIENT_OK_COUNT}, client_failed=${CLIENT_FAIL_COUNT}"
if [[ "${CLIENT_FAIL_COUNT}" -gt 0 ]]; then
  echo "[warn] Some clients failed; capture is still kept for analysis."
  echo "[warn] Check per-client logs in ${LOG_DIR} (run_id=${RUN_ID})."
fi
echo "[info] Logs are in: ${LOG_DIR}"
echo "[info] PCAP is in: ${PCAP_OUT}"

# Flush and close pcap writer before summary inspection.
stop_capture

if command -v capinfos >/dev/null 2>&1; then
  echo "[info] capinfos summary:"
  capinfos "${PCAP_OUT}" | sed -n '1,14p' || true
fi
