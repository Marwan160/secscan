#!/usr/bin/env bash
# modules/dns.sh - DNS-specific checks
#
# Exposes: dns_check <target> <port>

dns_check() {
    local target="$1" port="$2"
    local outfile="${REPORT_DIR}/dns_${port}.txt"

    if ! command -v dig >/dev/null 2>&1; then
        log_warn "dig not installed - skipping DNS zone transfer check"
        return
    fi

    # Try to determine a zone to test. If the target itself resolves to a domain
    # name (not just an IP), use it; otherwise attempt a reverse lookup first.
    local zone="$target"
    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        zone=$(dig -x "$target" +short 2>/dev/null | sed 's/\.$//' | head -n1)
    fi

    if [[ -z "$zone" ]]; then
        log_info "Could not determine a zone name to test for AXFR on port ${port}"
        return
    fi

    dig axfr "$zone" @"$target" -p "$port" > "$outfile" 2>&1

    if grep -qiE 'XFR size|; Transfer failed|communications error' "$outfile"; then
        if grep -qi 'Transfer failed\|communications error' "$outfile"; then
            log_info "Zone transfer refused for '${zone}' on ${target}:${port} (see ${outfile})"
        else
            log_finding \
                "DNS zone transfer (AXFR) allowed for zone '${zone}' on port ${port}" \
                "\`dig axfr ${zone} @${target} -p ${port}\` returned a full zone transfer:
$(sed 's/^/  /' "$outfile" | head -n 25)" \
                "High" \
                "Restrict AXFR to authorized secondary name servers only (allow-transfer directive)."
        fi
    else
        log_info "No successful zone transfer for '${zone}' on port ${port} (see ${outfile})"
    fi
}
