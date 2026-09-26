#!/usr/bin/env bash
# modules/ssh.sh - SSH-specific checks
#
# Exposes: ssh_check <target> <port>

ssh_check() {
    local target="$1" port="$2"
    local outfile="${REPORT_DIR}/ssh_${port}.txt"
    local banner=""

    if command -v nc >/dev/null 2>&1; then
        banner=$(timeout 5 bash -c "exec 3<>/dev/tcp/${target}/${port}; head -c 256 <&3" 2>/dev/null)
    fi

    if [[ -z "$banner" ]]; then
        banner=$(timeout 5 bash -c "exec 3<>/dev/tcp/${target}/${port}; head -1 <&3" 2>/dev/null)
    fi

    echo "$banner" > "$outfile"

    if [[ -z "$banner" ]]; then
        log_info "Could not retrieve SSH banner on port ${port}"
        return
    fi

    log_info "SSH banner on port ${port}: ${banner}"

    # Flag old/EOL protocol or software versions worth a human look.
    if echo "$banner" | grep -qiE 'SSH-1\.'; then
        log_finding \
            "Obsolete SSH protocol version 1 offered on port ${port}" \
            "Banner grab on ${target}:${port} returned: ${banner}" \
            "Critical" \
            "Disable SSHv1 support; require SSH protocol 2 only."
    elif echo "$banner" | grep -qiE 'OpenSSH_[1-6]\.'; then
        log_finding \
            "Outdated OpenSSH version banner on port ${port}" \
            "Banner grab on ${target}:${port} returned: ${banner}" \
            "Medium" \
            "Upgrade OpenSSH to a currently supported version and review CVEs for the reported release."
    else
        log_info "SSH version banner does not match known-outdated patterns"
    fi
}
