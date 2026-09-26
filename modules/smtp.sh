#!/usr/bin/env bash
# modules/smtp.sh - SMTP-specific checks
#
# Exposes: smtp_check <target> <port>

smtp_check() {
    local target="$1" port="$2"
    local outfile="${REPORT_DIR}/smtp_${port}.txt"

    if ! command -v nc >/dev/null 2>&1; then
        log_warn "nc (netcat) not installed - skipping SMTP checks"
        return
    fi

    # --- User enumeration via VRFY ---
    local vrfy_out
    vrfy_out=$(printf 'VRFY root\r\nVRFY nonexistent_user_zzz\r\nQUIT\r\n' | timeout 6 nc -w 5 "$target" "$port" 2>&1)
    echo "$vrfy_out" > "$outfile"

    if echo "$vrfy_out" | grep -qE '^25[0-9] '; then
        log_finding \
            "SMTP VRFY command enabled (user enumeration) on port ${port}" \
            "\`VRFY root\` against ${target}:${port} returned a 25x response, confirming the command is enabled:
$(echo "$vrfy_out" | sed 's/^/  /')" \
            "Medium" \
            "Disable the VRFY/EXPN commands on the mail server to prevent username enumeration."
    else
        log_info "SMTP VRFY does not appear to disclose valid users on port ${port}"
    fi

    # --- Open relay check ---
    local relay_out
    relay_out=$(printf 'HELO test\r\nMAIL FROM:<test@external-domain.example>\r\nRCPT TO:<test@another-external-domain.example>\r\nQUIT\r\n' \
        | timeout 6 nc -w 5 "$target" "$port" 2>&1)
    {
        echo "--- Open relay probe ---"
        echo "$relay_out"
    } >> "$outfile"

    if echo "$relay_out" | grep -qE '^250 .*(Recipient ok|OK|Ok)'; then
        log_finding \
            "Possible open mail relay on port ${port}" \
            "A MAIL FROM / RCPT TO test using two external, unrelated domains was accepted (250 OK):
$(echo "$relay_out" | sed 's/^/  /')" \
            "Critical" \
            "Reconfigure the MTA to only relay for authenticated users or trusted internal networks."
    else
        log_info "Server did not accept an external-to-external relay attempt on port ${port}"
    fi
}
