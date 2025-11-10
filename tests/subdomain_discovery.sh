#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

export TEST_DOMAIN="$1"
export OUTPUT_FILE="./tests/results/subdomain_discovery_${TEST_DOMAIN}.csv"

# Determine previous totals/domains if a prior run exists
PREV_TOTAL=0
PREV_DOMAINS=""
if [ -f "$OUTPUT_FILE" ]; then
    last_line=$(tail -n 1 "$OUTPUT_FILE")
    prev_total_candidate=$(echo "$last_line" | awk -F',' '{gsub(/"/,""); print $3}')
    if [[ "$prev_total_candidate" =~ ^[0-9]+$ ]]; then
        PREV_TOTAL="$prev_total_candidate"
        prev_domains_field=$(echo "$last_line" | cut -d',' -f4-)
        PREV_DOMAINS=$(echo "$prev_domains_field" | sed 's/^"//; s/"$//')
    fi
fi

echo "[+] Ensuring new image is built and ready to launch"
./tests/build_new_release.sh

export COMMAND="docker run osintscan:local discover dns subdomain passive --domain "$TEST_DOMAIN" --all-sources -o json | jq"
echo "[+] Running subdomain discovery"
echo "[+] Command: $COMMAND"
export RESULTS=$($COMMAND)

echo "[+] Checking if results are not empty"
if [ -z "$RESULTS" ]; then
    echo "[-] No results found"
    exit 1
fi

echo "[+] Checking if results contain $TEST_DOMAIN"
export DOMAINS=$(echo "$RESULTS" | jq -r '.content.result.subdomains[]')
export TOTAL_DOMAINS=$(echo "$RESULTS" | jq -r '.content.result.subdomains | length')
export DOMAINS_ARRAY=$(echo "$DOMAINS" | tr '\n' ' ')
export RUNTIME=$(echo "$RESULTS" | jq -r '.started_at')

# Compute delta and new domains vs previous run (if any)
DELTA=$((TOTAL_DOMAINS - PREV_TOTAL))
NEW_DOMAINS=""
NEW_COUNT=0
if [ -f "$OUTPUT_FILE" ]; then
    echo "  [+] Previous total: $PREV_TOTAL"
    echo "  [+] Current total:  $TOTAL_DOMAINS"
    if [ "$DELTA" -lt 0 ]; then
        echo "  [!] Error: current total ($TOTAL_DOMAINS) is less than previous ($PREV_TOTAL)"
        export ERROR=1
    else
        export ERROR=0
        for d in $DOMAINS; do
            case " $PREV_DOMAINS " in
                *" $d "*) ;; # already present
                *) NEW_DOMAINS="$NEW_DOMAINS $d"; NEW_COUNT=$((NEW_COUNT+1));;
            esac
        done
        NEW_DOMAINS="${NEW_DOMAINS# }"
        echo "  [+] Delta (new discovered): $DELTA"
        if [ "$NEW_COUNT" -gt 0 ]; then
            echo "  [+] New domains ($NEW_COUNT): $NEW_DOMAINS"
        fi
    fi
else
    export ERROR=0
fi

echo "[+] Saving Results to $OUTPUT_FILE"
if [ ! -f "$OUTPUT_FILE" ]; then
    echo "[+] File does not exist, Creating file"
    echo '"domain","start_time","total_domains","domains_found","command"' > "$OUTPUT_FILE"
fi

echo "\"$TEST_DOMAIN\",\"$RUNTIME\",\"$TOTAL_DOMAINS\",\"$DOMAINS_ARRAY\",\"$COMMAND\"" >> "$OUTPUT_FILE"

if [ "$ERROR" -eq 1 ]; then
    echo "[!] Error: current total ($TOTAL_DOMAINS) is less than previous ($PREV_TOTAL)"
    exit 1
else
    echo "[+] Found $TOTAL_DOMAINS domains for $TEST_DOMAIN"
fi
