#!/usr/bin/env bash
# modules/smb.sh - SMB-specific checks
#
# Exposes: smb_check <target> <port>

smb_check() {
    local target="$1" port="$2"
    local outfile="${REPORT_DIR}/smb_${port}.txt"

    if ! command -v smbclient >/dev/null 2>&1; then
        log_warn "smbclient not installed - skipping SMB share enumeration"
        return
    fi

    smbclient -L "//${target}/" -N > "$outfile" 2>&1

    if grep -qiE 'Sharename|Disk\s*\|' "$outfile"; then
        local shares
        shares=$(grep -iE 'Disk|IPC' "$outfile" | awk '{print $1}' | sort -u | tr '\n' ',' | sed 's/,$//')
        log_finding \
            "Unauthenticated SMB share listing on port ${port}" \
            "\`smbclient -L //${target}/ -N\` succeeded without credentials.
Shares discovered: ${shares}
Raw output:
$(sed 's/^/  /' "$outfile")" \
            "Medium" \
            "Require authentication for SMB share listing; disable null sessions/guest access."

        # Try to access each disk share anonymously to see if it's readable/writable.
        for share in $(grep -iE '\sDisk\s' "$outfile" | awk '{print $1}'); do
            local access_out
            access_out=$(smbclient "//${target}/${share}" -N -c 'ls' 2>&1)
            if ! echo "$access_out" | grep -qiE 'NT_STATUS_ACCESS_DENIED|NT_STATUS_LOGON_FAILURE'; then
                log_finding \
                    "Anonymous read access to SMB share '${share}' on port ${port}" \
                    "\`smbclient //${target}/${share} -N -c 'ls'\` returned a directory listing without credentials:
$(echo "$access_out" | sed 's/^/  /' | head -n 15)" \
                    "High" \
                    "Restrict share '${share}' to authenticated users and review its permissions."
            fi
        done
    else
        log_info "No unauthenticated SMB shares listed on port ${port} (see ${outfile})"
    fi
}
