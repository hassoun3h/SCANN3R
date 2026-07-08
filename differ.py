"""
differ.py
---------
Change-detection engine for SCANN3R.

Compares the current scan against the last stored scan for the same target
and reports every port whose state changed. This is the heart of the tool:
nmap tells you the state *now*, SCANN3R tells you what *changed* since last time.

A "change" is any transition between open / closed / filtered, plus ports that
newly appeared in the scan range or dropped out of it.
"""


def diff_scans(previous, current):
    """
    Compare two port-state dictionaries and return a list of changes.

    Args:
        previous: dict of {port: state} from the last scan, or None if this
                  is the first scan of the target.
        current:  dict of {port: state} from the scan just completed.

    Returns a list of change dicts, each shaped like:
        {
            "port": int,
            "old_state": str or None,   # None if the port is newly seen
            "new_state": str or None,   # None if the port dropped out
        }

    On a first-ever scan (previous is None), returns an empty list: there's
    no baseline to compare against, so nothing has "changed" yet. The scan is
    still saved so the next run has something to diff against.
    """
    # First scan: establish a baseline, report no changes.
    if previous is None:
        return []

    changes = []

    # Union of all ports seen in either scan. Using a set covers three cases:
    # ports in both, ports only in previous, ports only in current.
    all_ports = set(previous.keys()) | set(current.keys())

    for port in sorted(all_ports):
        old_state = previous.get(port)  # None if not in previous scan
        new_state = current.get(port)   # None if not in current scan

        # Record only genuine transitions. If old == new, nothing changed.
        if old_state != new_state:
            changes.append({
                "port": port,
                "old_state": old_state,
                "new_state": new_state,
            })

    return changes


def summarize_changes(changes):
    """
    Turn a raw change list into human-readable summary lines.

    Returns a list of strings like:
        "Port 22: open -> filtered"
        "Port 8080: (new) -> open"
        "Port 443: closed -> (gone)"

    Used by both the terminal output and the email alert body.
    """
    lines = []
    for change in changes:
        # Substitute a readable label when a side of the transition is None.
        old = change["old_state"] if change["old_state"] is not None else "(new)"
        new = change["new_state"] if change["new_state"] is not None else "(gone)"
        lines.append(f"Port {change['port']}: {old} -> {new}")
    return lines


def has_alertable_changes(changes):
    """
    Return True if there are any changes worth alerting on.

    Currently every change is alertable (per the design: any state change).
    Kept as a separate function so alert policy can be tightened later
    without touching the diff logic itself.
    """
    return len(changes) > 0
