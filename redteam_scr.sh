#!/bin/bash
#=======================
# Recon Script: origin_recon.sh
# Purpose: Discover origin IPs, WAF bypasses, and web app surfaces
# Platform: Kali, Parrot OS, Debian hardened distros
#Author: Sulaiman Basir
#Date: 2025-04-25
#=======================

set -euo pipefail

#--------- CONFIG ---------
TARGET_DOMAIN="$1"
OUTPUT_DIR="recon_output_${TARGET_DOMAIN}_$(date +%F_%H-%M)"
THREADS=50

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Logging setup
LOGFILE="$OUTPUT_DIR/recon.log"
echo "Starting recon on: $TARGET_DOMAIN" | tee "$LOGFILE"

#--------- FUNCTION DEFINITIONS ---------

function passive_enum() {
    echo "[+] Starting Passive Enumeration..." | tee -a "$LOGFILE"
    amass enum -passive -d "$TARGET_DOMAIN" -o "$OUTPUT_DIR/amass_passive.txt"
    curl -s "https://crt.sh/?q=%25.${TARGET_DOMAIN}&output=json" | jq -r '.[].name_value' | sort -u > "$OUTPUT_DIR/crtsh.txt"
}

function dns_brute_force() {
    echo "[+] Starting DNS Bruteforce..." | tee -a "$LOGFILE"
    subfinder -d "$TARGET_DOMAIN" -silent > "$OUTPUT_DIR/subfinder.txt"
    cat "$OUTPUT_DIR/subfinder.txt" | dnsx -resp-only -a -silent > "$OUTPUT_DIR/dnsx_resolved.txt"
}

function shodan_lookup() {
    echo "[+] Querying Shodan..." | tee -a "$LOGFILE"
    shodan search "ssl:$TARGET_DOMAIN" --fields ip_str,port,org,hostnames > "$OUTPUT_DIR/shodan_ssl.txt" || echo "[-] Shodan SSL lookup failed."
}

function cors_scan() {
    echo "[+] Performing CORS Scan..." | tee -a "$LOGFILE"
    if [ -s "$OUTPUT_DIR/dnsx_resolved.txt" ]; then
        cat "$OUTPUT_DIR/dnsx_resolved.txt" | httpx -silent -threads "$THREADS" -cors-scan > "$OUTPUT_DIR/cors_scan.txt"
    else
        echo "[-] No DNS resolved IPs to scan." | tee -a "$LOGFILE"
    fi
}

function nikto_web_scan() {
    echo "[+] Running Nikto Scan..." | tee -a "$LOGFILE"
    nikto -h "https://$TARGET_DOMAIN" -output "$OUTPUT_DIR/nikto_report.txt" || echo "[-] Nikto failed."
}

function skipfish_web_scan() {
    echo "[+] Running Skipfish Scan..." | tee -a "$LOGFILE"
    mkdir -p "$OUTPUT_DIR/skipfish"
    skipfish -o "$OUTPUT_DIR/skipfish" "https://$TARGET_DOMAIN" || echo "[-] Skipfish failed."
}

function header_spoofing_attack() {
    echo "[+] Attempting Header Spoofing (X-Forwarded-For)..." | tee -a "$LOGFILE"
    mkdir -p "$OUTPUT_DIR/header_spoof"
    for ip in $(seq 1 254); do
        curl -s -H "X-Forwarded-For: 127.0.0.$ip" "https://$TARGET_DOMAIN" -o "/dev/null" -w "%{http_code} - XFF: 127.0.0.$ip\n" >> "$OUTPUT_DIR/header_spoof/results.txt"
    done
}

#--------- EXECUTION FLOW ---------

passive_enum

dns_brute_force

shodan_lookup

cors_scan

nikto_web_scan

skipfish_web_scan

header_spoofing_attack

#--------- COMPLETION ---------

echo "[+] Recon Complete. Output saved in $OUTPUT_DIR" | tee -a "$LOGFILE"
echo "[+] Review $LOGFILE for command output summary."

exit 0
