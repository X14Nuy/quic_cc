#!/usr/bin/env bash
set -Eeuo pipefail

# -----------------------------------------------------------------------------
# Deploy source to remote host, build there, and start quic_secure_server.
# Use this when prebuilt binary is not ABI-compatible with remote runtime.
# -----------------------------------------------------------------------------

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLIENT_BIN="${PROJECT_ROOT}/build/quic_secure_client"
LOG_DIR="${PROJECT_ROOT}/CC_TEST/日志"

REMOTE_HOST=""
REMOTE_USER="root"
SSH_PORT="22"
REMOTE_DIR="/tmp/quic_secure_server_src"
PORT="4433"
ALPN="h3"
PSK_HEX=""
DO_LOCAL_CHECK="1"
INSTALL_DEPS="1"

usage() {
  cat <<USAGE
Usage: $(basename "$0") --host <ip_or_name> [options]

Options:
  --host <ip_or_name>        remote host (required)
  --user <username>          ssh username (default: ${REMOTE_USER})
  --ssh-port <port>          ssh port (default: ${SSH_PORT})
  --remote-dir <path>        remote working dir (default: ${REMOTE_DIR})
  --port <udp_port>          quic server port (default: ${PORT})
  --key <64hex>              shared key (if omitted, random generated)
  --alpn <value>             ALPN value (default: ${ALPN})
  --local-check <0|1>        run local protocol probe (default: ${DO_LOCAL_CHECK})
  --install-deps <0|1>       auto install build deps remotely (default: ${INSTALL_DEPS})
  -h, --help                 show this help

Example:
  $(basename "$0") --host 43.99.6.2 --user root --port 4433
USAGE
}

random_hex() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    printf "%08x%08x%08x%08x\n" "$RANDOM" "$RANDOM" "$RANDOM" "$RANDOM"
  fi
}

ssh_cmd() {
  ssh -p "${SSH_PORT}" \
    -o ConnectTimeout=8 \
    -o StrictHostKeyChecking=accept-new \
    "${REMOTE_USER}@${REMOTE_HOST}" "$@"
}

scp_cmd() {
  scp -P "${SSH_PORT}" \
    -o ConnectTimeout=8 \
    -o StrictHostKeyChecking=accept-new \
    "$@"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) REMOTE_HOST="$2"; shift 2 ;;
    --user) REMOTE_USER="$2"; shift 2 ;;
    --ssh-port) SSH_PORT="$2"; shift 2 ;;
    --remote-dir) REMOTE_DIR="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --key) PSK_HEX="$2"; shift 2 ;;
    --alpn) ALPN="$2"; shift 2 ;;
    --local-check) DO_LOCAL_CHECK="$2"; shift 2 ;;
    --install-deps) INSTALL_DEPS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "[error] unknown arg: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${REMOTE_HOST}" ]]; then
  echo "[error] --host is required" >&2
  exit 1
fi
if [[ "${DO_LOCAL_CHECK}" != "0" && "${DO_LOCAL_CHECK}" != "1" ]]; then
  echo "[error] --local-check must be 0|1" >&2
  exit 1
fi
if [[ "${INSTALL_DEPS}" != "0" && "${INSTALL_DEPS}" != "1" ]]; then
  echo "[error] --install-deps must be 0|1" >&2
  exit 1
fi
if [[ "${DO_LOCAL_CHECK}" == "1" && ! -x "${CLIENT_BIN}" ]]; then
  echo "[error] local probe needs ${CLIENT_BIN}, build local client first" >&2
  exit 1
fi

if [[ -z "${PSK_HEX}" ]]; then
  PSK_HEX="$(random_hex)"
fi

mkdir -p "${LOG_DIR}"
RUN_ID="$(date +%Y%m%d_%H%M%S)"
SRC_TAR="/tmp/qsc_src_${RUN_ID}.tar.gz"
PROBE_LOG="${LOG_DIR}/remote_src_probe_${RUN_ID}.log"
trap 'rm -f "${SRC_TAR}"' EXIT

echo "[info] packaging project source..."
tar -czf "${SRC_TAR}" \
  -C "${PROJECT_ROOT}" \
  CMakeLists.txt \
  include \
  src \
  tools \
  certs \
  README.md

echo "[info] creating remote workspace..."
ssh_cmd "mkdir -p '${REMOTE_DIR}' '${REMOTE_DIR}/logs'"

echo "[info] uploading source tarball..."
scp_cmd "${SRC_TAR}" "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/source.tar.gz"

echo "[info] building on remote host..."
ssh_cmd "
set -e
cd '${REMOTE_DIR}'

if [ '${INSTALL_DEPS}' = '1' ]; then
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y git cmake make gcc g++ pkg-config libpcap-dev libssl-dev ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y git cmake make gcc gcc-c++ pkgconfig libpcap-devel openssl-devel ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    yum install -y git cmake3 make gcc gcc-c++ pkgconfig libpcap-devel openssl-devel ca-certificates || true
    if ! command -v cmake >/dev/null 2>&1 && command -v cmake3 >/dev/null 2>&1; then
      ln -sf /usr/bin/cmake3 /usr/bin/cmake || true
    fi
  fi
fi

rm -rf src
mkdir -p src
tar -xzf source.tar.gz -C src
cd src

if ! command -v git >/dev/null 2>&1; then
  echo '[error] git is required by FetchContent(picoquic), but not found' >&2
  exit 2
fi

cmake -S . -B build
cmake --build build -j\$(nproc 2>/dev/null || echo 4)

if [ -f '${REMOTE_DIR}/server.pid' ]; then
  old_pid=\$(cat '${REMOTE_DIR}/server.pid' 2>/dev/null || true)
  if [ -n \"\$old_pid\" ] && kill -0 \"\$old_pid\" 2>/dev/null; then
    kill -TERM \"\$old_pid\" || true
    sleep 1
  fi
fi

nohup '${REMOTE_DIR}/src/build/quic_secure_server' \
  -p '${PORT}' \
  -k '${PSK_HEX}' \
  -a '${ALPN}' \
  -C '${REMOTE_DIR}/src/certs/cert.pem' \
  -K '${REMOTE_DIR}/src/certs/key.pem' \
  > '${REMOTE_DIR}/logs/server.log' 2>&1 < /dev/null &
echo \$! > '${REMOTE_DIR}/server.pid'
sleep 1

pid=\$(cat '${REMOTE_DIR}/server.pid')
if ! kill -0 \"\$pid\" 2>/dev/null; then
  echo '[error] remote server failed to start' >&2
  tail -n 120 '${REMOTE_DIR}/logs/server.log' >&2 || true
  exit 3
fi
echo '[ok] remote server pid='\"\$pid\"
if command -v ss >/dev/null 2>&1; then
  ss -lun | grep -E '[:.]${PORT}[[:space:]]' || true
fi
"

if [[ "${DO_LOCAL_CHECK}" == "1" ]]; then
  echo "[info] running local protocol probe..."
  if command -v timeout >/dev/null 2>&1; then
    timeout 25 "${CLIENT_BIN}" \
      -s "${REMOTE_HOST}" \
      -p "${PORT}" \
      -k "${PSK_HEX}" \
      -m "probe_src_${RUN_ID}" > "${PROBE_LOG}" 2>&1
  else
    "${CLIENT_BIN}" \
      -s "${REMOTE_HOST}" \
      -p "${PORT}" \
      -k "${PSK_HEX}" \
      -m "probe_src_${RUN_ID}" > "${PROBE_LOG}" 2>&1
  fi
  echo "[ok] local probe completed, log=${PROBE_LOG}"
fi

echo "[ok] remote source-build deploy completed"
echo "[ok] key=${PSK_HEX}"
echo "[next] remote log:"
echo "       ssh -p ${SSH_PORT} ${REMOTE_USER}@${REMOTE_HOST} \"tail -f ${REMOTE_DIR}/logs/server.log\""
echo "[next] stop service:"
echo "       ssh -p ${SSH_PORT} ${REMOTE_USER}@${REMOTE_HOST} \"kill -TERM \$(cat ${REMOTE_DIR}/server.pid)\""

