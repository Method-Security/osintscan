#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

export TEST_DOMAIN="$1"
export OUTPUT_FILE="./tests/results/subdomain_discovery_${TEST_DOMAIN}.csv"

run_subdomain_discovery() {
    local cmd="$1"
    export COMMAND="$cmd"
    echo "[+] Running subdomain discovery"
    echo "[+] Command: $COMMAND"
    export RESULTS=$(eval "$COMMAND")

    echo "[+] Checking if results are not empty"
    if [ -z "$RESULTS" ]; then
        echo "[-] No results found"
        return 1
    fi

    echo "[+] Checking if results contain $TEST_DOMAIN"
    export DOMAINS=$(echo "$RESULTS" | jq -r '.content.result.subdomains[]?')
    export TOTAL_DOMAINS=$(echo "$RESULTS" | jq -r '.content.result.subdomains | length')
    export DOMAINS_ARRAY=$(echo "$DOMAINS" | tr '\n' ' ')
    export RUNTIME=$(echo "$RESULTS" | jq -r '.started_at')
    echo "[+] Found $TOTAL_DOMAINS domains for $TEST_DOMAIN"
    return 0
}

echo "[+] Ensuring new image is built and ready to launch"
./tests/build_new_release.sh

echo "[+] Saving Results to $OUTPUT_FILE"
if [ ! -f "$OUTPUT_FILE" ]; then
    echo "[+] File does not exist, Creating file"
    echo '"domain","start_time","total_domains","domains_found","command"' > "$OUTPUT_FILE"
fi

# Run with --all-sources
CMD_ALL="docker run osintscan:local discover dns subdomain passive --domain \"$TEST_DOMAIN\" --all-sources -o json | jq"
run_subdomain_discovery "$CMD_ALL"
echo "\"$TEST_DOMAIN\",\"$RUNTIME\",\"$TOTAL_DOMAINS\",\"$DOMAINS_ARRAY\",\"$COMMAND\"" >> "$OUTPUT_FILE"

# Run without --all-sources
CMD_DEFAULT="docker run osintscan:local discover dns subdomain passive --domain \"$TEST_DOMAIN\" -o json | jq"
run_subdomain_discovery "$CMD_DEFAULT"
echo "\"$TEST_DOMAIN\",\"$RUNTIME\",\"$TOTAL_DOMAINS\",\"$DOMAINS_ARRAY\",\"$COMMAND\"" >> "$OUTPUT_FILE"
