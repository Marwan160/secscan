#!/usr/bin/env bash
# modules/http.sh - HTTP/HTTPS-specific checks
#
# Exposes: http_check <target> <port> <scheme>

http_check() {
    local target="$1" port="$2" scheme="${3:-http}"
    local outfile="${REPORT_DIR}/http_${port}.txt"
    local base_url="${scheme}://${target}:${port}"

    if ! command -v curl >/dev/null 2>&1; then
        log_warn "curl not installed - skipping HTTP enumeration"
        return
    fi

    # --- Headers ---
    local headers
    headers=$(curl -sk -I --max-time 8 "$base_url/" 2>&1)
    {
        echo "=== Headers: ${base_url}/ ==="
        echo "$headers"
        echo ""
    } > "$outfile"

    log_info "Retrieved HTTP headers from ${base_url}/"

    local server_hdr
    server_hdr=$(echo "$headers" | grep -i '^Server:' | tr -d '\r')
    if [[ -n "$server_hdr" ]]; then
        log_info "Server header: ${server_hdr}"
    fi

    if ! echo "$headers" | grep -qi '^X-Frame-Options:'; then
        log_finding \
            "Missing X-Frame-Options header on ${base_url}/" \
            "\`curl -I ${base_url}/\` response headers:
$(echo "$headers" | sed 's/^/  /')
(no X-Frame-Options header present)" \
            "Low" \
            "Add X-Frame-Options (or a CSP frame-ancestors directive) to mitigate clickjacking."
    fi

    # --- robots.txt ---
    local robots
    robots=$(curl -sk --max-time 8 "$base_url/robots.txt" 2>&1)
    {
        echo "=== robots.txt: ${base_url}/robots.txt ==="
        echo "$robots"
        echo ""
    } >> "$outfile"

    if [[ -n "$robots" ]] && ! echo "$robots" | grep -qi '404 not found'; then
        local disallowed
        disallowed=$(echo "$robots" | grep -i '^Disallow:' | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')
        if [[ -n "$disallowed" ]]; then
            log_finding \
                "robots.txt discloses potentially sensitive paths on ${base_url}/" \
                "\`curl ${base_url}/robots.txt\` returned Disallow entries: ${disallowed}
Full content:
$(echo "$robots" | sed 's/^/  /')" \
                "Low" \
                "Avoid listing sensitive admin/internal paths in robots.txt; enforce access control server-side instead."
        fi
    else
        log_info "No robots.txt found (or empty) on ${base_url}/"
    fi

    # --- Basic common path probe ---
    for path in admin login .git/HEAD phpinfo.php; do
        local code
        code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 "$base_url/${path}")
        if [[ "$code" == "200" ]]; then
            log_finding \
                "Exposed path /${path} on ${base_url}" \
                "\`curl -o /dev/null -w '%{http_code}' ${base_url}/${path}\` returned HTTP 200." \
                "Medium" \
                "Review whether /${path} should be publicly accessible; restrict or remove it if not."
        fi
    done
}
