#!/usr/bin/env bash
# modules/ftp.sh - FTP-specific checks
#
# Exposes: ftp_check <target> <port>

ftp_check() {
    local target="$1" port="$2"
    local outfile="${REPORT_DIR}/ftp_${port}.txt"

    if ! command -v ftp >/dev/null 2>&1; then
        log_warn "ftp client not installed - skipping anonymous login check"
        return
    fi

    # Attempt anonymous login non-interactively.
    {
        printf 'user anonymous anonymous@example.com\nls\nbye\n'
    } | ftp -inv "$target" "$port" > "$outfile" 2>&1

    if grep -qiE '230|Login successful' "$outfile"; then
        local listing
        listing=$(grep -A 20 -iE '^[0-9]+' "$outfile" | tail -n 15)
        log_finding \
            "Anonymous FTP login allowed on port ${port}" \
            "\`ftp ${target} ${port}\` -> logged in as 'anonymous' successfully.
Session output:
$(sed 's/^/  /' "$outfile" | tail -n 20)" \
            "High" \
            "Disable anonymous FTP access unless explicitly required; restrict write permissions."
    else
        log_info "Anonymous FTP login not permitted on port ${port} (see ${outfile} for evidence)"
    fi
}
