"""
alerter.py
----------
Email alerting for SCANN3R.

When the diff engine detects state changes, this module sends a summary email
via SMTP. Credentials and server settings come from config.py, which reads
them from environment variables so nothing sensitive is hardcoded.

Uses only the Python standard library (smtplib + email), so there are no extra
dependencies to install for alerting.
"""

import smtplib
from email.message import EmailMessage

from config import (
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USER,
    SMTP_PASSWORD,
    ALERT_FROM,
    ALERT_TO,
)


def build_alert_body(target, ip, timestamp, summary_lines):
    """
    Assemble the plain-text body of a change-alert email.

    Kept separate from sending so it can be unit-tested and reused (e.g. for
    a future Slack/webhook alerter) without touching SMTP code.
    """
    header = (
        f"SCANN3R detected port state changes.\n\n"
        f"Target:    {target}\n"
        f"Resolved:  {ip}\n"
        f"Scan time: {timestamp}\n\n"
        f"Changes ({len(summary_lines)}):\n"
    )
    body = header + "\n".join(f"  - {line}" for line in summary_lines)
    return body


def send_alert(target, ip, timestamp, summary_lines):
    """
    Send a change-alert email.

    Args:
        target: the scanned target string.
        ip: resolved IP.
        timestamp: scan timestamp.
        summary_lines: list of human-readable change strings from
                       differ.summarize_changes().

    Returns True on success, False on failure. Failures are non-fatal: a scan
    should still be saved even if the alert can't be delivered, so the caller
    logs the failure and moves on rather than crashing.
    """
    # Guard against a half-configured environment. If SMTP settings are
    # missing, skip sending rather than raising deep in the send path.
    if not all([SMTP_HOST, SMTP_USER, SMTP_PASSWORD, ALERT_FROM, ALERT_TO]):
        print("[alerter] SMTP not fully configured; skipping email alert.")
        return False

    # Construct the message.
    msg = EmailMessage()
    msg["Subject"] = f"[SCANN3R] Port changes on {target}"
    msg["From"] = ALERT_FROM
    msg["To"] = ALERT_TO
    msg.set_content(build_alert_body(target, ip, timestamp, summary_lines))

    try:
        # Use SMTP over TLS. starttls upgrades the plaintext connection to
        # encrypted before we send credentials.
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        print(f"[alerter] Alert email sent to {ALERT_TO}.")
        return True
    except Exception as e:
        # Broad catch on purpose: any SMTP/network failure should degrade
        # gracefully rather than lose the scan.
        print(f"[alerter] Failed to send alert email: {e}")
        return False
