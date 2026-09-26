#!/usr/bin/env bash
#
# secscan.sh - Mini automated security assessment framework
#
# Usage:
#   ./secscan.sh <target>
#   ./secscan.sh <targets_file.txt>
#   ./secscan.sh --help | --version
#
# Only scan targets you own or have explicit written permission to test.

set -uo pipefail

# ---------------------------------------------------------------------------
# Globals & paths
# ---------------------------------------------------------------------------
VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="${SCRIPT_DIR}/modules"
TIMESTAMP="$(date '+%Y-%m-%d_%H-%M-%S')"

# Populated per-target in run_scan()
TARGET=""
REPORT_DIR=""
SCAN_FILE=""
FINDINGS_FILE=""
SUMMARY_FILE=""
FINDINGS_COUNT=0

# Associative array: detected open ports -> service name
declare -A OPEN_PORTS

# ---------------------------------------------------------------------------
# Logging helpers (stdout + persisted to scan.txt)
# ---------------------------------------------------------------------------
log_info()    { echo -e "[*] $*"; [[ -n "$SCAN_FILE" ]] && echo "[*] $*" >> "$SCAN_FILE"; }
log_success() { echo -e "[+] $*"; [[ -n "$SCAN_FILE" ]] && echo "[+] $*" >> "$SCAN_FILE"; }
log_warn()    { echo -e "[!] $*"; [[ -n "$SCAN_FILE" ]] && echo "[!] $*" >> "$SCAN_FILE"; }
log_error()   { echo -e "[-] $*" >&2; [[ -n "$SCAN_FILE" ]] && echo "[-] $*" >> "$SCAN_FILE"; }

# Record a finding. Every finding MUST include evidence (mandatory requirement).
# Usage: log_finding "<title>" "<evidence text>" "<risk: Low|Medium|High|Critical>" "<recommendation>"
log_finding() {
    local title="$1" evidence="$2" risk="$3" recommendation="$4"
    FINDINGS_COUNT=$((FINDINGS_COUNT + 1))
    log_warn "$title"
    {
        echo "Finding #${FINDINGS_COUNT}: ${title}"
        echo "  Risk:           ${risk}"
        echo "  Evidence:"
        echo "${evidence}" | sed 's/^/    /'
        echo "  Recommendation: ${recommendation}"
        echo ""
    } >> "$FINDINGS_FILE"
}

# ---------------------------------------------------------------------------
# Usage / version
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
Usage: $(basename "$0") <target>
       $(basename "$0") <targets_file.txt>
       $(basename "$0") --help
       $(basename "$0") --version

  <target>         A single IP address or hostname to assess.
  <targets_file>   A text file with one target per line (bonus: multi-target mode).

Options:
  --help, -h       Show this help message and exit.
  --version, -v    Show version information and exit.

Examples:
  ./secscan.sh 192.168.56.10
  ./secscan.sh targets.txt
EOF
}

version() {
    echo "secscan.sh version ${VERSION}"
}

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------
# Mandatory: without these, no meaningful scan can happen.
REQUIRED_TOOLS=(nmap ping)
# Optional: individual modules degrade gracefully (with a warning) if missing.
OPTIONAL_TOOLS=(dig smbclient curl ftp nc whois host)

check_dependencies() {
    local missing_required=0

    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log_error "${tool} is not installed"
            missing_required=1
        fi
    done

    if [[ "$missing_required" -eq 1 ]]; then
        exit 3
    fi

    for tool in "${OPTIONAL_TOOLS[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log_warn "Optional dependency '${tool}' not found - related checks will be skipped"
        fi
    done
}

# ---------------------------------------------------------------------------
# Reachability check
# ---------------------------------------------------------------------------
check_reachable() {
    if ! ping -c 2 -W 2 "$TARGET" >/dev/null 2>&1; then
        log_error "Target is unreachable"
        return 1
    fi
    log_success "Target ${TARGET} is reachable"
    return 0
}

# ---------------------------------------------------------------------------
# 4.1 Reconnaissance
# ---------------------------------------------------------------------------
recon() {
    log_info "Starting reconnaissance on ${TARGET}..."
    {
        echo "=== Reconnaissance: ${TARGET} ==="
        echo "Scan date: $(date)"
        echo ""
        echo "-- Hostname / DNS resolution --"
        if command -v host >/dev/null 2>&1; then
            host "$TARGET" 2>&1 || echo "  (resolution failed / no PTR record)"
        else
            getent hosts "$TARGET" 2>&1 || echo "  (resolution failed)"
        fi
        echo ""
        echo "-- Basic network info (ping statistics) --"
        ping -c 3 -W 2 "$TARGET" 2>&1 | tail -n 4
        echo ""
    } | tee -a "$SCAN_FILE"
}

# ---------------------------------------------------------------------------
# 4.2 Port & Service Enumeration
# ---------------------------------------------------------------------------
port_scan() {
    log_info "Running TCP port & service scan (nmap -sV -Pn)..."
    local raw_out="${REPORT_DIR}/nmap_raw.txt"

    nmap -sV -Pn -T4 "$TARGET" > "$raw_out" 2>&1
    local rc=$?

    {
        echo "=== Port & Service Enumeration: ${TARGET} ==="
        cat "$raw_out"
        echo ""
    } >> "$SCAN_FILE"

    if [[ $rc -ne 0 ]]; then
        log_error "nmap scan failed (exit code ${rc})"
        return 1
    fi

    # Parse "PORT STATE SERVICE VERSION" lines into a structured table.
    # Example line: 22/tcp open ssh OpenSSH 7.2p2 Ubuntu ...
    while IFS= read -r line; do
        local port proto service
        port=$(echo "$line" | awk -F'/' '{print $1}')
        proto=$(echo "$line" | awk -F'/' '{print $2}' | awk '{print $1}')
        service=$(echo "$line" | awk '{print $3}')
        [[ -z "$port" || -z "$service" ]] && continue
        OPEN_PORTS["$port"]="$service"
    done < <(grep -E '^[0-9]+/tcp[[:space:]]+open' "$raw_out")

    log_success "Detected ${#OPEN_PORTS[@]} open port(s)"

    {
        echo "-- Structured open port summary --"
        printf "%-8s %-15s\n" "PORT" "SERVICE"
        for p in "${!OPEN_PORTS[@]}"; do
            printf "%-8s %-15s\n" "$p" "${OPEN_PORTS[$p]}"
        done
        echo ""
    } >> "$SCAN_FILE"

    return 0
}

# ---------------------------------------------------------------------------
# 4.3 Automated Enumeration - decision logic
# ---------------------------------------------------------------------------
run_service_modules() {
    if [[ ${#OPEN_PORTS[@]} -eq 0 ]]; then
        log_warn "No open ports detected - skipping service-specific enumeration"
        return
    fi

    for port in "${!OPEN_PORTS[@]}"; do
        local svc="${OPEN_PORTS[$port]}"
        case "$svc" in
            ftp)
                log_success "FTP detected on port ${port}"
                log_info "Starting FTP enumeration..."
                ftp_check "$TARGET" "$port"
                ;;
            ssh)
                log_success "SSH detected on port ${port}"
                log_info "Starting SSH banner/version check..."
                ssh_check "$TARGET" "$port"
                ;;
            microsoft-ds|netbios-ssn|smb)
                log_success "SMB detected on port ${port}"
                log_info "Starting SMB enumeration..."
                smb_check "$TARGET" "$port"
                ;;
            smtp)
                log_success "SMTP detected on port ${port}"
                log_info "Starting SMTP enumeration..."
                smtp_check "$TARGET" "$port"
                ;;
            domain)
                log_success "DNS detected on port ${port}"
                log_info "Starting DNS zone transfer check..."
                dns_check "$TARGET" "$port"
                ;;
            http|http-proxy|http-alt)
                log_success "HTTP detected on port ${port}"
                log_info "Starting HTTP enumeration..."
                http_check "$TARGET" "$port" "http"
                ;;
            https|ssl/http)
                log_success "HTTPS detected on port ${port}"
                log_info "Starting HTTP(S) enumeration..."
                http_check "$TARGET" "$port" "https"
                ;;
            *)
                log_info "No specific module for service '${svc}' on port ${port} - skipping"
                ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# 4.5 Report generation
# ---------------------------------------------------------------------------
generate_summary() {
    local risk="Informational"
    if [[ "$FINDINGS_COUNT" -ge 1 ]]; then risk="Low"; fi
    if [[ "$FINDINGS_COUNT" -ge 3 ]]; then risk="Medium"; fi
    if [[ "$FINDINGS_COUNT" -ge 5 ]]; then risk="High"; fi

    {
        echo "=================================================="
        echo " Security Assessment Summary"
        echo "=================================================="
        echo "Target:          ${TARGET}"
        echo "Scan date:       $(date)"
        echo "Open ports:      ${#OPEN_PORTS[@]}"
        for p in "${!OPEN_PORTS[@]}"; do
            echo "  - ${p}/tcp (${OPEN_PORTS[$p]})"
        done
        echo "Total findings:  ${FINDINGS_COUNT}"
        echo "Overall risk:    ${risk}"
        echo ""
        if [[ "$FINDINGS_COUNT" -eq 0 ]]; then
            echo "No security issues were flagged by the automated checks run"
            echo "against the detected services. This does not guarantee the"
            echo "target is fully secure - it only reflects the checks performed."
        else
            echo "See findings.txt for full evidence-backed details of each issue."
        fi
        echo ""
        echo "General recommendations:"
        echo "  - Disable or restrict any anonymous/unauthenticated access."
        echo "  - Keep all detected services patched and up to date."
        echo "  - Apply the principle of least privilege on exposed shares/services."
        echo "  - Re-run this assessment after remediation to confirm fixes."
    } > "$SUMMARY_FILE"

    log_success "Summary written to ${SUMMARY_FILE}"
}

generate_html_report() {
    local html_file="${REPORT_DIR}/report.html"
    {
        echo "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        echo "<title>Security Assessment - ${TARGET}</title>"
        echo "<style>body{font-family:Arial,sans-serif;margin:40px;background:#f7f5f0;color:#222}"
        echo "h1{color:#c1440e}h2{border-bottom:2px solid #c1440e;padding-bottom:4px}"
        echo "pre{background:#1e1e1e;color:#eee;padding:12px;border-radius:6px;overflow-x:auto}"
        echo "table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:6px 10px;text-align:left}"
        echo "</style></head><body>"
        echo "<h1>Bash Security Assessment Report</h1>"
        echo "<p><b>Target:</b> ${TARGET}<br><b>Date:</b> $(date)</p>"
        echo "<h2>Open Ports</h2><table><tr><th>Port</th><th>Service</th></tr>"
        for p in "${!OPEN_PORTS[@]}"; do
            echo "<tr><td>${p}/tcp</td><td>${OPEN_PORTS[$p]}</td></tr>"
        done
        echo "</table>"
        echo "<h2>Findings (${FINDINGS_COUNT})</h2><pre>"
        [[ -s "$FINDINGS_FILE" ]] && sed 's/</\&lt;/g; s/>/\&gt;/g' "$FINDINGS_FILE" || echo "No findings recorded."
        echo "</pre>"
        echo "<h2>Summary</h2><pre>"
        sed 's/</\&lt;/g; s/>/\&gt;/g' "$SUMMARY_FILE"
        echo "</pre></body></html>"
    } > "$html_file"
    log_success "HTML report written to ${html_file}"
}

# ---------------------------------------------------------------------------
# Per-target orchestration
# ---------------------------------------------------------------------------
run_scan() {
    TARGET="$1"
    FINDINGS_COUNT=0
    OPEN_PORTS=()

    REPORT_DIR="${SCRIPT_DIR}/reports/${TARGET//[^a-zA-Z0-9._-]/_}_${TIMESTAMP}"
    mkdir -p "$REPORT_DIR"
    SCAN_FILE="${REPORT_DIR}/scan.txt"
    FINDINGS_FILE="${REPORT_DIR}/findings.txt"
    SUMMARY_FILE="${REPORT_DIR}/summary.txt"
    : > "$SCAN_FILE"
    : > "$FINDINGS_FILE"

    echo "=================================================="
    echo " Assessing target: ${TARGET}"
    echo "=================================================="

    if ! check_reachable; then
        echo "Target: ${TARGET} - unreachable, scan aborted at $(date)" > "$SUMMARY_FILE"
        return 1
    fi

    recon
    if port_scan; then
        run_service_modules
    fi
    generate_summary
    generate_html_report

    log_success "Report saved in: ${REPORT_DIR}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    if [[ $# -eq 0 ]]; then
        usage
        exit 1
    fi

    case "$1" in
        --help|-h)
            usage
            exit 0
            ;;
        --version|-v)
            version
            exit 0
            ;;
    esac

    check_dependencies

    # Source service modules
    for mod in ftp ssh smb smtp dns http; do
        # shellcheck source=/dev/null
        source "${MODULES_DIR}/${mod}.sh"
    done

    local input="$1"
    local exit_code=0

    if [[ -f "$input" ]]; then
        log_info "Multi-target mode: reading targets from ${input}"
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            run_scan "$line" || exit_code=1
        done < "$input"
    else
        run_scan "$input" || exit_code=1
    fi

    exit "$exit_code"
}

main "$@"
