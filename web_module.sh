#!/bin/bash

# Improvements to make: 
# Use of not standard port consideration 
# Export append to global CSV vuln export
# custom or default wordlists 
# wordlist generation module 
# webhooks and heartbeat to signal ends of larger looped scans with minimal threads (auto detect) 
#
# Fix ascii art and menu system
#
# Script: web_preliminary_testing.sh
# Purpose: Perform preliminary web vulnerability scanning using Nikto and Gobuster
# Usage: ./web_preliminary_testing.sh web_servers_list.txt

if [ $# -ne 1 ]; then
    echo "Usage: $0 web_servers_list.txt"
    exit 1
fi

WEB_SERVERS_FILE="$1"


if [ ! -f "$WEB_SERVERS_FILE" ]; then
    echo "Error: File '$WEB_SERVERS_FILE' not found."
    exit 1
fi

OUTPUT_DIR="$HOME/nmap_scanner/results/web_scans"
TIMESTAMP=$(date +%F_%H-%M-%S)
mkdir -p "$OUTPUT_DIR"

# Check for required commands
REQUIRED_CMDS=("nikto" "gobuster" "curl")
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: Required command '$cmd' not found. Please install it before running the script."
        exit 1
    fi
done

perform_nikto_scan() {
    local target_url="$1"
    local output_file="$2"
    echo "Running Nikto scan on $target_url..."
    nikto -h "$target_url" -o "$output_file" -Format txt
    echo "Nikto scan completed for $target_url. Results saved to $output_file"
}


perform_gobuster_scan() {
    local target_url="$1"
    local output_file="$2"
    echo "Running Gobuster scan on $target_url..."
    gobuster dir -u "$target_url" -w /usr/share/wordlists/dirb/common.txt -o "$output_file"
    echo "Gobuster scan completed for $target_url. Results saved to $output_file"
}


while read -r line; do
    ip_port="$line"
    ip="${ip_port%%:*}"
    port="${ip_port##*:}"

    if [ "$port" -eq 443 ] || [ "$port" -eq 8443 ]; then
        protocol="https"
    else
        protocol="http"
    fi

    target_url="$protocol://$ip:$port"


    nikto_output="$OUTPUT_DIR/nikto_${ip}_${port}_$TIMESTAMP.txt"
    gobuster_output="$OUTPUT_DIR/gobuster_${ip}_${port}_$TIMESTAMP.txt"
    perform_nikto_scan "$target_url" "$nikto_output"
    perform_gobuster_scan "$target_url" "$gobuster_output"

done < "$WEB_SERVERS_FILE"

echo "All scans completed. Results are stored in $OUTPUT_DIR"
