# SCANN3R

A change-detection TCP port scanner. Where a normal port scanner tells you what's open *right now*, SCANN3R tells you what *changed* since the last time you scanned. Built for security teams who need to know when a target's exposed surface shifts: a new port opening, a service disappearing, or a firewall rule silently changing.

## Why this exists

nmap answers "what is the state of this host?" SCANN3R answers "what is different about this host since I last looked?" It stores every scan, compares each new scan against the previous one for the same target, and alerts by email on any port that changed state (open, closed, or filtered).

Typical uses:
- Monitoring your own external attack surface for unexpected changes
- Catching a service that got exposed by a misconfiguration
- Tracking whether a remediation actually closed a port and kept it closed

## Requirements

- Python 3.8 or newer
- No third-party packages required for scanning, storage, diffing, or email alerts (standard library only)

## Installation

```bash
git clone https://github.com/hassoun3h/SCANN3R.git
cd SCANN3R
```

That's it. There's nothing to compile and no dependencies to install.

## Quick start

Run your first scan:

```bash
python3 scann3r.py scan --target scanme.nmap.org --ports 1-1024
```

The first scan of any target sets a baseline: it's saved, but there's nothing to compare against yet. Run the same command again later and SCANN3R will report anything that changed.

## Commands

### `scan` — run a scan and detect changes

```bash
python3 scann3r.py scan --target <host> [options]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--target` | *(required)* | Hostname or IP to scan |
| `--ports` | `1-1024` | Ports to scan. Ranges, lists, or both: `1-1024`, `22,80,443`, `1-100,8080` |
| `--timeout` | `1.0` | Per-port connection timeout in seconds |
| `--workers` | `100` | Number of concurrent threads |
| `--db` | `scann3r.db` | SQLite database file to use |

Example scanning a specific set of ports with a faster timeout:

```bash
python3 scann3r.py scan --target 10.0.0.5 --ports 22,80,443,3389,8080 --timeout 0.5
```

### `history` — show recent scans for a target

```bash
python3 scann3r.py history --target 10.0.0.5 --limit 10
```

### `targets` — list everything you've ever scanned

```bash
python3 scann3r.py targets
```

## Email alerts

When a scan detects changes, SCANN3R can email a summary. Configuration is read entirely from environment variables so no credentials live in the code:

```bash
export SCANN3R_SMTP_HOST="smtp.gmail.com"
export SCANN3R_SMTP_PORT="587"
export SCANN3R_SMTP_USER="you@example.com"
export SCANN3R_SMTP_PASSWORD="your-app-password"
export SCANN3R_ALERT_FROM="you@example.com"
export SCANN3R_ALERT_TO="soc-team@example.com"
```

If these aren't set, scanning still works normally; the email step is simply skipped. Alerts are non-fatal: if the mail server is unreachable, the scan result is still saved and the failure is logged.

For Gmail specifically you'll need an app password (regular account passwords won't work with SMTP when 2FA is on).

## Understanding port states

SCANN3R distinguishes three states, and transitions between any of them count as a change:

- **open** — something is actively listening
- **closed** — the host is reachable but nothing is on that port (connection refused)
- **filtered** — no response before the timeout, usually a firewall dropping packets

The closed-vs-filtered distinction matters. A port going `open -> filtered` often means a firewall rule appeared, which is a different signal than a service simply stopping (`open -> closed`).

## A note on responsible use

Only scan systems you own or have explicit written authorization to test. Unauthorized port scanning may be illegal in your jurisdiction. This tool is for defensive monitoring of your own infrastructure.

## License

See LICENSE file.
