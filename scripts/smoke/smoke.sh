#!/usr/bin/env bash
#
# osintscan dependency-bump smoke test.
#
# Purpose: this repo has ZERO hand-written unit tests. The 419 test functions
# under generated/ are Fern-generated JSON round-trips of the API models; they
# exercise encoding/json and nothing else. Every module that govulncheck flags
# in this repo is a *transitive* dependency (x/crypto, x/net, utls, goldmark,
# compress, rardecode reach us through amass, subfinder, dnsx and miekg/dns),
# so `go build` passing tells us the parent libraries still compile against the
# bumped versions -- and nothing about whether they still work.
#
# This script closes that gap: it stands up a local authoritative DNS server
# (scripts/smoke/dnsserver.py) and drives the real CLI against it, so the full
# miekg/dns wire path is exercised for real. It also walks the whole cobra
# command tree, which forces the init() of every imported package -- that is
# what catches an init-time panic from a bumped transitive dep.
#
# All traffic is to 127.0.0.1. The script makes no external network requests,
# which also means it needs no API keys and cannot be rate-limited.
#
# PLATFORM NOTE. osintscan used to segfault at startup on darwin/arm64 --
# gopsutil v3 pulls github.com/shoenig/go-m1cpu, whose cgo initialize() faulted
# on macOS 26 (Darwin 25.x). That is fixed as of go-m1cpu v0.2.2, so this
# script now runs natively everywhere. Set SMOKE_DOCKER=1 to force the Linux
# container path anyway -- useful for reproducing what CI (ubuntu-latest) sees.
#
# Usage:  scripts/smoke/smoke.sh [path-to-osintscan-binary]
#         SMOKE_DOCKER=1 scripts/smoke/smoke.sh    # force the container path
# Exit:   0 = all checks passed, 1 = one or more checks failed

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${1:-}"

# ------------------------------------------------------------ container re-exec
# Opt-in: rebuild for Linux and re-run this same script inside a container that
# has python3, to reproduce the platform CI actually builds on.
if [[ "${SMOKE_IN_CONTAINER:-}" != "1" && "${SMOKE_DOCKER:-}" == "1" ]]; then
  echo "SMOKE_DOCKER=1; building a Linux binary and running the checks in a container"
  command -v docker >/dev/null || { echo "SMOKE_DOCKER=1 requires docker" >&2; exit 1; }
  LINUX_BIN="$(mktemp -d)/osintscan"
  ( cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" \
      go build -mod=vendor -o "$LINUX_BIN" . ) || { echo "linux build failed" >&2; exit 1; }
  exec docker run --rm \
    -e SMOKE_IN_CONTAINER=1 \
    -v "$LINUX_BIN:/osintscan:ro" \
    -v "$REPO_ROOT/scripts/smoke:/smoke:ro" \
    python:3-alpine \
    sh -c 'apk add --no-cache bash >/dev/null 2>&1 && bash /smoke/smoke.sh /osintscan'
fi

WORKDIR="$(mktemp -d)"
DNS_PORT="${SMOKE_DNS_PORT:-$(python3 -c 'import socket
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1",0))
print(s.getsockname()[1]); s.close()')}"
PASS=0
FAIL=0

cleanup() {
  [[ -n "${DNS_PID:-}" ]] && kill "$DNS_PID" 2>/dev/null
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()  { printf '  \033[32mPASS\033[0m  %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAIL=$((FAIL+1)); }

# ---------------------------------------------------------------- build binary
if [[ -z "$BIN" ]]; then
  BIN="$WORKDIR/osintscan"
  say "Building osintscan"
  if ! (cd "$REPO_ROOT" && go build -mod=vendor -o "$BIN" . 2>"$WORKDIR/build.err"); then
    grep -v 'warning:' "$WORKDIR/build.err" >&2
    echo "build failed" >&2
    exit 1
  fi
fi
echo "binary: $BIN"
if ! "$BIN" version >/dev/null 2>&1; then
  echo "cannot execute $BIN -- wrong architecture, not a file, or not executable" >&2
  exit 1
fi

# ------------------------------------------------------------- local DNS zone
DNSSERVER="$(dirname "${BASH_SOURCE[0]}")/dnsserver.py"
[[ -f "$DNSSERVER" ]] || DNSSERVER=/smoke/dnsserver.py
say "Starting local authoritative DNS server on 127.0.0.1:$DNS_PORT"
python3 "$DNSSERVER" "$DNS_PORT" >"$WORKDIR/dns.log" 2>&1 &
DNS_PID=$!
for _ in $(seq 1 40); do
  grep -q READY "$WORKDIR/dns.log" 2>/dev/null && break
  sleep 0.25
done
if ! grep -q READY "$WORKDIR/dns.log" 2>/dev/null; then
  echo "local DNS server failed to start" >&2
  cat "$WORKDIR/dns.log" >&2
  exit 1
fi
RESOLVER="127.0.0.1:$DNS_PORT"
echo "resolver: $RESOLVER   zone: smoke.test"

# ------------------------------------------------------------------- assertions
check() {
  local name="$1"; shift
  local want_exit="$1"; shift
  local out="$WORKDIR/out.json"
  "$@" >"$out" 2>"$WORKDIR/err.txt"
  local got=$?
  if [[ "$got" != "$want_exit" ]]; then
    bad "$name (exit $got, wanted $want_exit)"
    sed -n '1,6p' "$WORKDIR/err.txt" | sed 's/^/        /'
    return
  fi
  if [[ " $* " == *" -o json "* ]]; then
    if ! python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$out" 2>/dev/null; then
      bad "$name (exit ok but output is not valid JSON)"
      head -c 200 "$out" | sed 's/^/        /'; echo
      return
    fi
  fi
  ok "$name"
}

# jsoncheck <name> <python-expr-over-d> <cmd...>
#   Asserts a predicate over the parsed JSON, so we prove the query actually
#   resolved rather than returning a well-formed empty envelope. The predicate
#   travels via the environment, never through shell interpolation into the
#   Python source -- predicates contain quotes.
jsoncheck() {
  local name="$1"; shift
  local expr="$1"; shift
  local out="$WORKDIR/out.json"
  "$@" >"$out" 2>"$WORKDIR/err.txt"
  local got=$?
  if [[ "$got" != 0 ]]; then
    bad "$name (exit $got)"
    sed -n '1,6p' "$WORKDIR/err.txt" | sed 's/^/        /'
    return
  fi
  if SMOKE_EXPR="$expr" python3 -c '
import json, os, sys
d = json.load(open(sys.argv[1]))
expr = os.environ["SMOKE_EXPR"]
if not eval(expr):
    sys.exit("predicate false: " + expr)
' "$out" 2>"$WORKDIR/pred.err"; then
    ok "$name"
  else
    bad "$name ($(tail -1 "$WORKDIR/pred.err"))"
    head -c 300 "$out" | sed 's/^/        /'; echo
  fi
}

# =============================================================================
say "1. Command tree loads (forces init of amass, subfinder, dnsx, utls, x/crypto)"
# This is the highest-value check in the file. Every vulnerable module in this
# repo is transitive, and most are reached through package init -- the openpgp
# s2k registration that govulncheck traces runs at init of the subfinder runner.
# A bumped transitive dep that breaks at init dies right here.
check "root help"              0 "$BIN" --help
for sub in discover enumerate pentest; do
  check "$sub help"            0 "$BIN" "$sub" --help
done
check "discover dns help"      0 "$BIN" discover dns --help
check "version"                0 "$BIN" version

say "2. DNS records against the local zone (miekg/dns, full wire path)"
jsoncheck "records ALL" \
  "'192.0.2.10' in str(d)" \
  "$BIN" discover dns records --domain smoke.test --dns-resolvers "$RESOLVER" -o json
jsoncheck "records A" \
  "'192.0.2.10' in str(d)" \
  "$BIN" discover dns records --domain smoke.test --record-types A --dns-resolvers "$RESOLVER" -o json
jsoncheck "records MX" \
  "'mail.smoke.test' in str(d)" \
  "$BIN" discover dns records --domain smoke.test --record-types MX --dns-resolvers "$RESOLVER" -o json
jsoncheck "records TXT" \
  "'smoke-test-marker' in str(d)" \
  "$BIN" discover dns records --domain smoke.test --record-types TXT --dns-resolvers "$RESOLVER" -o json
jsoncheck "records NS" \
  "'ns1.smoke.test' in str(d)" \
  "$BIN" discover dns records --domain smoke.test --record-types NS --dns-resolvers "$RESOLVER" -o json
jsoncheck "records AAAA" \
  "'2001:db8::10' in str(d).lower()" \
  "$BIN" discover dns records --domain smoke.test --record-types AAAA --dns-resolvers "$RESOLVER" -o json
jsoncheck "records CNAME (www -> apex)" \
  "'smoke.test' in str(d)" \
  "$BIN" discover dns records --domain www.smoke.test --record-types CNAME --dns-resolvers "$RESOLVER" -o json

say "3. NXDOMAIN is reported, not crashed on"
check "records NXDOMAIN"       0 "$BIN" discover dns records --domain nope.smoke.test --dns-resolvers "$RESOLVER" -o json

say "4. Output writers (signal + yaml, Method-Security/pkg)"
check "output yaml"            0 "$BIN" discover dns records --domain smoke.test --record-types A --dns-resolvers "$RESOLVER" -o yaml
check "output signal"          0 "$BIN" discover dns records --domain smoke.test --record-types A --dns-resolvers "$RESOLVER" -o signal

say "5. Unreachable resolver is handled without a panic"
"$BIN" discover dns records --domain smoke.test --dns-resolvers 127.0.0.1:1 -o json \
  >"$WORKDIR/dead.json" 2>"$WORKDIR/dead.err"
if grep -q "panic:" "$WORKDIR/dead.err" "$WORKDIR/dead.json" 2>/dev/null; then
  bad "dead resolver handled without panic"
  grep -m3 -A3 "panic:" "$WORKDIR/dead.err" | sed 's/^/        /'
else
  ok "dead resolver handled without panic"
fi

# =============================================================================
say "Result"
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
