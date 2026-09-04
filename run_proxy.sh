#!/usr/bin/env bash
# =============================================================================
# run_proxy.sh — LLM Secrets Proxy management (v1.1.0) for testing and headless
# deployment
#
# Usage:
#   ./run_proxy.sh start [PORT]     starts the service (LOCKED if vault is
#                                   encrypted)
#   ./run_proxy.sh stop             stops the service
#   ./run_proxy.sh restart [PORT]
#   ./run_proxy.sh status           health + pid
#   ./run_proxy.sh logs [N]         last N log lines (default 30)
#   ./run_proxy.sh unlock           unlocks the vault (asks for the passphrase)
#   ./run_proxy.sh lock             wipes state (503 until the next unlock)
#   ./run_proxy.sh upstream [URL]   show/set the upstream
#
# Configuration via env (all optional):
#   SECRETS_PROXY_HOST=0.0.0.0          bind address (default 0.0.0.0: LAN
#                                       deploy on VM .223 — restrict sources
#                                       with the IP whitelist from the
#                                       dashboard)
#   SECRETS_PROXY_PORT=8917
#   SECRETS_PROXY_VAULT=<path>          default: vault.txt next to this script
#   SECRETS_PROXY_KEY=<Fernet key>      mode B: auto-load at startup (headless);
#                                       do NOT set it for mode A (manual
#                                       unlock)
#   SECRETS_PROXY_API_KEY=<token>       admin token (unlock/lock/remote)
#   SECRETS_PROXY_PASSPHRASE=...        for NON-interactive unlock (script/test)
#   SECRETS_PROXY_UPSTREAM=URL          overrides the persisted config
# service_config.json (keys read at startup):
#   "open_mode": true|false             client token not required on the proxy
#   "trusted_ips": ["ip", ...]          IP whitelist in open mode ([] = all)
# =============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST="${SECRETS_PROXY_HOST:-0.0.0.0}"
PORT="${SECRETS_PROXY_PORT:-8917}"
# flat layout: the code (core/service/dashboard/vaultctl) lives next to this script
ROOT="$SCRIPT_DIR"
RUN_DIR="$SCRIPT_DIR/run"
PIDFILE="$RUN_DIR/secrets_proxy.pid"
LOGFILE="$RUN_DIR/secrets_proxy.log"
VAULT="${SECRETS_PROXY_VAULT:-$ROOT/vault.txt}"
BASE_URL="http://$HOST:$PORT"

mkdir -p "$RUN_DIR" 2>/dev/null && chmod 700 "$RUN_DIR" 2>/dev/null

if [ -n "${SECRETS_PROXY_KEY:-}" ]; then
    MODE_DESC="B (auto-key ${SECRETS_PROXY_KEY:0:4}...)"
else
    MODE_DESC="A (manual unlock)"
fi

if [ -f "$SCRIPT_DIR/vaultctl.py" ]; then VCTL="$SCRIPT_DIR/vaultctl.py"
elif [ -f "$ROOT/vaultctl.py" ];      then VCTL="$ROOT/vaultctl.py"
else echo "vaultctl.py not found (searched in $SCRIPT_DIR and $ROOT)" >&2; exit 1; fi

_vctl() { \
    SECRETS_PROXY_BASE_URL="$BASE_URL" \
    SECRETS_PROXY_API_KEY="${SECRETS_PROXY_API_KEY:-}" \
    python3 "$VCTL" ${SECRETS_PROXY_PASSPHRASE:+--passphrase "$SECRETS_PROXY_PASSPHRASE"} "$@"; }

_health() { curl -s --max-time 2 "$BASE_URL/health" 2>/dev/null; }

_pid_alive() { [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }

cmd_start() {
    PORT="${2:-$PORT}"; BASE_URL="http://$HOST:$PORT"
    if _pid_alive; then
        echo "already running (pid $(cat "$PIDFILE")) — use restart or stop"; exit 1
    fi
    if [ ! -f "$VAULT" ]; then
        echo "WARNING: vault missing: $VAULT (the service will start LOCKED)" >&2
        echo "         create it with: python3 vaultctl.py add <entry>" >&2
    fi
    echo "[run_proxy] start: vault=$VAULT host=$HOST port=$PORT $MODE_DESC"
    ( cd "$ROOT" \
      && export SECRETS_PROXY_VAULT="$VAULT" SECRETS_PROXY_PORT="$PORT" \
      && export SECRETS_PROXY_API_KEY="${SECRETS_PROXY_API_KEY:-}" \
      && export SECRETS_PROXY_KEY="${SECRETS_PROXY_KEY:-}" \
      && export SECRETS_PROXY_UPSTREAM="${SECRETS_PROXY_UPSTREAM:-}" \
      && exec nohup python3 -m uvicorn service:app \
           --host "$HOST" --port "$PORT" --log-level warning \
           >> "$LOGFILE" 2>&1 ) &
    echo $! > "$PIDFILE"
    for _ in $(seq 1 30); do
        if [ -n "$(_health)" ]; then break; fi; sleep 0.5
    done
    cmd_status
}

cmd_stop() {
    local killed=""
    if _pid_alive; then
        kill "$(cat "$PIDFILE")" 2>/dev/null && killed=1
        for _ in $(seq 1 20); do _pid_alive || break; sleep 0.3; done
        _pid_alive && kill -9 "$(cat "$PIDFILE")" 2>/dev/null
        rm -f "$PIDFILE"
    fi
    # fallback: the service may have been started with a different pid than the pidfile
    if [ -n "$(_health)" ]; then
        pkill -f "uvicorn service:app --host $HOST --port $PORT" 2>/dev/null
        for _ in $(seq 1 20); do [ -z "$(_health)" ] && break; sleep 0.3; done
    fi
    if [ -z "$(_health)" ]; then
        echo "[run_proxy] stop ok${killed:+ (pid)}"; rm -f "$PIDFILE"
    else
        echo "ERROR: the service does not stop — process still listening on $PORT" >&2
        ss -ltnp 2>/dev/null | grep ":$PORT " >&2
        exit 1
    fi
}

cmd_status() {
    local h; h=$(_health)
    if [ -z "$h" ]; then
        local hint=""; _pid_alive && hint=" — pid $(cat "$PIDFILE") exists but is not responding: check logs ($LOGFILE)"
        echo "OFFLINE ($BASE_URL)$hint"
        exit 1
    fi
    echo "$h" | python3 -c '
import sys, json
d = json.load(sys.stdin)
print("ONLINE %s — secrets:%s named:%s patterns:%s uptime:%.0fs" % (
    str(d.get("status","?")).upper(), d.get("secrets","?"), d.get("named","?"),
    d.get("patterns","?"), float(d.get("uptime_s") or 0)))
print("stats:", d.get("stats"))'
    _pid_alive && echo "pid $(cat "$PIDFILE") — log: $LOGFILE"
}

cmd_logs() { tail -"${2:-30}" "$LOGFILE" 2>/dev/null || echo "no logs"; }

cmd_unlock() { _vctl unlock; }
cmd_lock()   { _vctl lock; }
cmd_upstream() { shift 2>/dev/null; _vctl upstream "${1:-}"; }

case "${1:-help}" in
    start)   cmd_start "$@" ;;
    stop)    cmd_stop ;;
    restart) cmd_stop; sleep 1; cmd_start "$@" ;;
    status)  cmd_status ;;
    logs)    cmd_logs "$@" ;;
    unlock)  cmd_unlock ;;
    lock)    cmd_lock ;;
    upstream) cmd_upstream "$@" ;;
    *) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//' ;;
esac