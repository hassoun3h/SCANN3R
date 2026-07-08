"""
scanner.py
----------
Core scanning logic for SCANN3R.

Performs a threaded TCP connect scan against a target host. Unlike a raw
SYN scan (which requires root privileges), a full TCP connect scan uses the
standard socket API and works without elevated permissions. The tradeoff is
that connect scans are slightly noisier on the target, but for change-detection
in an authorized enterprise context that is not a concern.

Threading via ThreadPoolExecutor lets us scan thousands of ports concurrently,
cutting scan time from many minutes down to seconds.
"""

import socket
import concurrent.futures
from datetime import datetime, timezone


# Default number of worker threads. 100 is a safe balance that keeps scans
# fast without exhausting file descriptors or tripping aggressive rate limits.
DEFAULT_WORKERS = 100

# Default per-port connection timeout in seconds. Ports that don't respond
# within this window are treated as filtered (silently dropped by a firewall).
DEFAULT_TIMEOUT = 1.0


def resolve_target(target):
    """
    Resolve a hostname to an IPv4 address.

    Accepts either a raw IP or a hostname. Returns the resolved IP string,
    or raises socket.gaierror if resolution fails (caller handles that).
    """
    return socket.gethostbyname(target)


def scan_port(ip, port, timeout=DEFAULT_TIMEOUT):
    """
    Attempt a TCP connection to a single port.

    Returns one of three states:
      - "open"     : connection succeeded (something is listening)
      - "closed"   : connection actively refused (host reachable, nothing there)
      - "filtered" : no response before timeout (firewall likely dropping packets)

    Distinguishing closed vs filtered is what makes change-detection meaningful:
    a port going open -> filtered can indicate a firewall rule change, not just
    a service stopping.
    """
    # Create a fresh socket per port. AF_INET = IPv4, SOCK_STREAM = TCP.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        # connect_ex returns an error code instead of raising, which is
        # cleaner for high-volume scanning. 0 means the connection opened.
        result = sock.connect_ex((ip, port))
        if result == 0:
            return "open"
        else:
            # Any non-zero, non-timeout result means the host actively
            # responded that the port is closed (e.g. RST packet).
            return "closed"
    except socket.timeout:
        # No response at all within the timeout window.
        return "filtered"
    except OSError:
        # Network unreachable, too many open files, etc. Treat as filtered
        # so the scan continues rather than crashing.
        return "filtered"
    finally:
        # Always release the socket, even on error, to avoid leaking
        # file descriptors across a large scan.
        sock.close()


def scan_target(target, ports, timeout=DEFAULT_TIMEOUT, workers=DEFAULT_WORKERS,
                progress_callback=None):
    """
    Scan a range of ports on a target concurrently.

    Args:
        target: hostname or IP string.
        ports: iterable of port numbers to scan.
        timeout: per-port connection timeout in seconds.
        workers: number of concurrent threads.
        progress_callback: optional function called with (done, total) after
                           each port completes, for progress display.

    Returns a dict with scan metadata and results:
        {
            "target": original target string,
            "ip": resolved IP,
            "timestamp": ISO 8601 UTC timestamp of scan start,
            "ports": { port_number: state, ... }
        }

    Raises socket.gaierror if the target cannot be resolved.
    """
    ip = resolve_target(target)
    timestamp = datetime.now(timezone.utc).isoformat()

    ports = list(ports)
    total = len(ports)
    results = {}
    done = 0

    # ThreadPoolExecutor manages the worker pool for us. We submit one
    # scan_port task per port and collect results as they finish.
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        # Map each future back to its port so we know which result is which.
        future_to_port = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in ports
        }

        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            results[port] = future.result()
            done += 1
            if progress_callback:
                progress_callback(done, total)

    return {
        "target": target,
        "ip": ip,
        "timestamp": timestamp,
        "ports": results,
    }


def get_service_name(port):
    """
    Look up the well-known service name for a port (e.g. 80 -> 'http').

    Uses the system services database via socket.getservbyport. Returns
    'unknown' if there's no registered name. Purely cosmetic, for readability
    in reports.
    """
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"
