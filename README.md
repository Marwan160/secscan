# secscan.sh — Bash-Based Security Assessment Tool

A mini automated security assessment framework written in pure Bash.
Given a target, it performs reconnaissance, TCP port & service enumeration,
then automatically runs service-specific checks and produces a structured,
evidence-based report.

> ⚠️ **Only run this against systems you own or have explicit written
> permission to test.** Use isolated lab VMs on a host-only network adapter.

## Features

- Reconnaissance: reachability check, DNS/hostname info, basic network info
- Port & service enumeration via `nmap -sV`, parsed into a structured table
- Decision-driven service modules:
  - **FTP** — anonymous login check
  - **SSH** — banner/version check, flags outdated versions
  - **SMB** — unauthenticated share listing + per-share read access check
  - **SMTP** — VRFY user enumeration + open relay probe
  - **DNS** — zone transfer (AXFR) check
  - **HTTP/HTTPS** — headers, robots.txt, common exposed paths
- Every finding is logged with concrete evidence (command run + output), a
  risk rating, and a recommendation — never just a label
- Structured report per target: `scan.txt`, `findings.txt`, `summary.txt`,
  plus a bonus `report.html`
- Multi-target mode: pass a text file of targets instead of a single host
- `--help` / `--version` flags
- Proper exit codes, dependency checks, and unreachable-target handling

## Usage

```bash
chmod +x secscan.sh
./secscan.sh <target>          # single target
./secscan.sh targets.txt       # one target per line
./secscan.sh --help
./secscan.sh --version
```

Reports are written to `reports/<target>_<timestamp>/`.

## Project layout

```
secscan/
├── secscan.sh          # main script: args, recon, scanning, orchestration, reporting
├── modules/
│   ├── ftp.sh
│   ├── ssh.sh
│   ├── smb.sh
│   ├── smtp.sh
│   ├── dns.sh
│   └── http.sh
├── reports/             # generated per-target output (git-ignored)
└── README.md
```

## Requirements

- Bash 4+ (uses associative arrays)
- `nmap` (required)
- Optional, for full coverage: `dig`, `smbclient`, `curl`, `ftp`, `nc`, `host`

Missing optional tools don't crash the scan — the related module is skipped
with a warning so the rest of the assessment still completes.

## Design notes

- **Decision logic**: the script never assumes what's running. It parses
  `nmap`'s service field for each open port and dispatches to the matching
  module (`case` statement in `run_service_modules`). Unknown services are
  logged and skipped rather than guessed at.
- **Evidence-first findings**: `log_finding()` is the single choke point for
  recording an issue — it requires a title, raw evidence, a risk level, and a
  recommendation, so it's structurally impossible to log a bare "X is
  vulnerable" label.
- **Failure handling**: missing `nmap`/`ping` aborts with exit code 3; an
  unreachable target aborts that target's scan (but not the whole batch in
  multi-target mode) and still produces a summary noting why.
- **Multi-target mode** just treats the first argument as a targets file when
  it exists on disk, otherwise as a literal target — no separate flag needed.

## What I implemented myself / hardest part

*(fill this in for your submission — the brief asks you to describe this in
your own words for the review session).*
