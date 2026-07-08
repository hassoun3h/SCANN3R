"""
config.py
---------
Central configuration for SCANN3R.

All sensitive values (SMTP credentials, recipient addresses) are read from
environment variables rather than hardcoded. This keeps secrets out of the
codebase and out of version control, which matters especially for a security
tool destined for a public portfolio repo.

Set these in your shell, a .env file loaded by your process manager, or your
CI/CD secrets store. Nothing here should ever contain a real credential.
"""

import os


# ---------------------------------------------------------------------------
# SMTP / email alert settings
# ---------------------------------------------------------------------------
# SMTP server hostname, e.g. "smtp.gmail.com" or an internal relay.
SMTP_HOST = os.environ.get("SCANN3R_SMTP_HOST", "")

# SMTP port. 587 is the standard for STARTTLS submission.
SMTP_PORT = int(os.environ.get("SCANN3R_SMTP_PORT", "587"))

# Username for SMTP auth (often the same as the from address).
SMTP_USER = os.environ.get("SCANN3R_SMTP_USER", "")

# Password or app-specific password for SMTP auth.
SMTP_PASSWORD = os.environ.get("SCANN3R_SMTP_PASSWORD", "")

# The "From" address shown on alert emails.
ALERT_FROM = os.environ.get("SCANN3R_ALERT_FROM", "")

# Where alerts are delivered. A single address for now; could be extended
# to a comma-separated list later.
ALERT_TO = os.environ.get("SCANN3R_ALERT_TO", "")


# ---------------------------------------------------------------------------
# Scan defaults
# ---------------------------------------------------------------------------
# Default port range if the user doesn't specify one. 1-1024 covers the
# well-known ports where most services of interest live.
DEFAULT_PORT_RANGE = "1-1024"

# Default database file path.
DEFAULT_DB_PATH = os.environ.get("SCANN3R_DB_PATH", "scann3r.db")
