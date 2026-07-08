#!/usr/bin/env python3
"""
scann3r.py
----------
Command-line entry point for SCANN3R, a change-detection port scanner.

SCANN3R scans a target's ports, stores the result, and compares it against the
previous scan of the same target. Any port that changed state (open, closed,
filtered) is reported and, if configured, emailed as an alert.

Commands:
    scan      Run a scan and diff it against the last one.
    history   Show recent scans for a target.
    targets   List all targets ever scanned.

Run `python scann3r.py <command> --help` for command-specific options.
"""

import sys
import argparse
import socket

import scanner
import store
import differ
import alerter
import config


def parse_ports(port_spec):
    """
    Parse a port specification string into a list of port numbers.

    Accepts:
        "1-1024"        -> range 1 through 1024 inclusive
        "22,80,443"     -> explicit list
        "80"            -> single port
        "1-100,443,8080"-> mixed ranges and singles

    Returns a sorted list of unique ints. Raises ValueError on malformed input.
    """
    ports = set()
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            # Range like "1-1024".
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            # Single port.
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"Port out of range: {p}")
            ports.add(p)
    return sorted(ports)


def _progress(done, total):
    """Simple in-place progress indicator printed to stderr."""
    pct = (done / total) * 100
    # \r returns to line start so the counter updates in place.
    print(f"\rScanning... {done}/{total} ports ({pct:.0f}%)",
          end="", file=sys.stderr, flush=True)


def cmd_scan(args):
    """
    Handle the 'scan' subcommand: scan, store, diff, and alert.
    """
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(f"Target: {args.target}  |  Ports: {len(ports)}  |  "
          f"Timeout: {args.timeout}s  |  Threads: {args.workers}")

    # Run the scan. Catch resolution failures cleanly.
    try:
        result = scanner.scan_target(
            args.target,
            ports,
            timeout=args.timeout,
            workers=args.workers,
            progress_callback=_progress,
        )
    except socket.gaierror:
        print(f"\nError: could not resolve '{args.target}'.", file=sys.stderr)
        return 1
    print()  # newline after the progress indicator

    # Open the database and diff against the last scan BEFORE saving the new one.
    conn = store.init_db(args.db)
    previous = store.get_last_scan(conn, args.target)
    changes = differ.diff_scans(previous, result["ports"])

    # Persist the new scan regardless of whether anything changed.
    store.save_scan(conn, result)

    # Report open ports found in this scan.
    open_ports = sorted(p for p, s in result["ports"].items() if s == "open")
    if open_ports:
        print(f"\nOpen ports ({len(open_ports)}):")
        for port in open_ports:
            print(f"  {port:>5}  {scanner.get_service_name(port)}")
    else:
        print("\nNo open ports found.")

    # Report and alert on changes.
    if previous is None:
        print("\nFirst scan of this target. Baseline saved; no diff to report.")
    elif differ.has_alertable_changes(changes):
        summary = differ.summarize_changes(changes)
        print(f"\nChanges since last scan ({len(summary)}):")
        for line in summary:
            print(f"  {line}")

        # Fire the email alert. Non-fatal if it fails.
        alerter.send_alert(
            result["target"], result["ip"], result["timestamp"], summary
        )
    else:
        print("\nNo changes since last scan.")

    conn.close()
    return 0


def cmd_history(args):
    """Handle the 'history' subcommand: show recent scans for a target."""
    conn = store.init_db(args.db)
    rows = store.get_history(conn, args.target, limit=args.limit)
    conn.close()

    if not rows:
        print(f"No scan history for '{args.target}'.")
        return 0

    print(f"Recent scans for {args.target}:")
    for r in rows:
        print(f"  #{r['id']:<5} {r['timestamp']}  ({r['ip']})")
    return 0


def cmd_targets(args):
    """Handle the 'targets' subcommand: list all scanned targets."""
    conn = store.init_db(args.db)
    rows = store.list_targets(conn)
    conn.close()

    if not rows:
        print("No targets scanned yet.")
        return 0

    print("Scanned targets:")
    for r in rows:
        print(f"  {r['target']:<30} {r['scan_count']:>3} scans  "
              f"(last: {r['last_scan']})")
    return 0


def build_parser():
    """
    Construct the argparse CLI. Each subcommand maps to a cmd_* handler.
    """
    parser = argparse.ArgumentParser(
        prog="scann3r",
        description="Change-detection TCP port scanner.",
    )
    # Global --db flag so all subcommands can point at a custom database file.
    parser.add_argument(
        "--db", default=config.DEFAULT_DB_PATH,
        help=f"SQLite database file (default: {config.DEFAULT_DB_PATH})",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # --- scan ---
    p_scan = sub.add_parser("scan", help="Scan a target and diff against last scan.")
    p_scan.add_argument("--target", required=True, help="Hostname or IP to scan.")
    p_scan.add_argument(
        "--ports", default=config.DEFAULT_PORT_RANGE,
        help=f"Port spec, e.g. '1-1024' or '22,80,443' "
             f"(default: {config.DEFAULT_PORT_RANGE}).",
    )
    p_scan.add_argument(
        "--timeout", type=float, default=scanner.DEFAULT_TIMEOUT,
        help=f"Per-port timeout in seconds (default: {scanner.DEFAULT_TIMEOUT}).",
    )
    p_scan.add_argument(
        "--workers", type=int, default=scanner.DEFAULT_WORKERS,
        help=f"Concurrent threads (default: {scanner.DEFAULT_WORKERS}).",
    )
    p_scan.set_defaults(func=cmd_scan)

    # --- history ---
    p_hist = sub.add_parser("history", help="Show recent scans for a target.")
    p_hist.add_argument("--target", required=True, help="Hostname or IP.")
    p_hist.add_argument("--limit", type=int, default=10, help="Max rows (default: 10).")
    p_hist.set_defaults(func=cmd_history)

    # --- targets ---
    p_tgt = sub.add_parser("targets", help="List all scanned targets.")
    p_tgt.set_defaults(func=cmd_targets)

    return parser


def main():
    """Parse args and dispatch to the selected subcommand handler."""
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        # Ctrl+C during a scan should exit cleanly, not dump a traceback.
        print("\nInterrupted.", file=sys.stderr)
        return 130


# Standard entry-point guard so the module can be imported without executing.
if __name__ == "__main__":
    sys.exit(main())
