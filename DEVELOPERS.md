# SCANN3R — Developer Documentation

This document explains the internal architecture for anyone extending or maintaining SCANN3R. For usage instructions, see `README.md`.

## Design goals

1. **Standard library only** for core functionality. Anyone can clone and run it with zero `pip install`. This keeps the tool portable and auditable, which matters for a security utility.
2. **Separation of concerns.** Scanning, storage, diffing, and alerting are independent modules with no circular dependencies. Each can be tested or replaced in isolation.
3. **Fail soft.** A scan should never be lost because an alert failed to send or one port errored. Failures degrade gracefully and are logged.

## Module map

```
scann3r.py    CLI entry point + argument parsing + command dispatch
scanner.py    Threaded TCP connect scanning; DNS resolution; service lookup
store.py      SQLite persistence: schema, save, and query functions
differ.py     State comparison between two scans; change summarization
alerter.py    SMTP email alerting; message construction
config.py     Environment-variable-based configuration
```

Dependency direction is strictly one-way. `scann3r.py` imports the other modules; `alerter.py` imports `config.py`. Nothing imports `scann3r.py`. There are no cycles.

## Data flow for a scan

```
CLI (scann3r.py: cmd_scan)
  -> scanner.scan_target()          # returns {target, ip, timestamp, ports}
  -> store.get_last_scan()          # fetch previous {port: state} or None
  -> differ.diff_scans()            # compute list of changes
  -> store.save_scan()              # persist the new scan
  -> differ.summarize_changes()     # human-readable lines
  -> alerter.send_alert()           # email if changes + SMTP configured
```

The order matters: the diff is computed against the previous scan **before** the new scan is written, otherwise the new scan would become its own baseline.

## Scanning internals (`scanner.py`)

- Uses `socket.connect_ex()` rather than `connect()` so a closed port returns an error code instead of raising, which is cleaner at high volume.
- `ThreadPoolExecutor` runs up to `workers` concurrent connections. TCP connect scanning is I/O-bound (mostly waiting on network), so threads are effective here despite the GIL — the GIL is released during blocking socket calls.
- Three states are returned. The `closed` vs `filtered` distinction comes from whether the socket was actively refused (closed) or timed out silently (filtered).

**Why not Scapy / SYN scanning?** A raw SYN scan needs root and raw-socket privileges. A connect scan doesn't, which makes the tool far easier to deploy and run in restricted environments. For change detection specifically, connect scanning gives identical signal.

## Storage schema (`store.py`)

Two normalized tables:

```sql
scans(id, target, ip, timestamp)
port_results(id, scan_id -> scans.id, port, state)
```

One `scans` row per run, one `port_results` row per port per run. This lets you reconstruct the full port state of any target at any historical point, which is what makes diffing possible. An index on `scans(target, timestamp)` keeps "latest scan for target" lookups fast as history grows.

All writes for a single scan happen in one transaction (`save_scan`), so an interrupted scan never leaves a half-written record.

## Diff logic (`differ.py`)

`diff_scans(previous, current)` takes the union of ports across both scans and records any port where `old_state != new_state`. Ports present in only one scan are handled by representing the missing side as `None` (rendered as `(new)` or `(gone)` in summaries).

`has_alertable_changes()` is intentionally a separate one-liner. Right now it alerts on every change, but isolating the policy here means you can later add filtering (e.g. only alert on newly opened ports) without touching the comparison logic.

## Alerting (`alerter.py`)

- `build_alert_body()` is separated from `send_alert()` so the message text can be unit-tested and reused by future alerters (Slack, webhook) without duplicating formatting.
- SMTP uses STARTTLS on port 587 by default.
- If SMTP config is incomplete, `send_alert()` returns `False` and logs a skip rather than raising.

## Extension points

The design anticipates several planned expansions:

- **Scheduled scanning.** Currently on-demand only. A scheduler (cron, or an internal loop) would just call `cmd_scan` logic on a timer. No core changes needed.
- **Additional alert channels.** Add a `slack.py` / `webhook.py` mirroring `alerter.py`'s interface. The diff summary is already channel-agnostic.
- **Alert policy tuning.** Tighten `has_alertable_changes()` to filter by transition type.
- **Multiple recipients.** `ALERT_TO` is a single address today; splitting on commas is a small change in `alerter.py`.
- **UDP scanning.** Would require a new scan function in `scanner.py`; the storage and diff layers are protocol-agnostic and wouldn't change.

## Testing notes

Manual end-to-end test used during development:

1. Scan a target with a known-closed port to set a baseline.
2. Start a local listener (`socket.bind` + `listen`) on that port.
3. Re-scan. The tool should report `closed -> open` for that port.

For automated tests, the natural seams are `diff_scans` (pure function, trivial to unit test), `parse_ports` (pure, edge cases around ranges), and `build_alert_body` (pure, deterministic output). The scanning and SMTP layers are best covered with integration tests against local listeners and a mock SMTP server.

## Code style

- Comments explain *why*, not *what*. The what is in the code.
- Each public function has a docstring covering args, return shape, and failure behavior.
- No hardcoded secrets anywhere; all sensitive config comes from environment variables via `config.py`.
