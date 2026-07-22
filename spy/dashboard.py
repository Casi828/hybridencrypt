"""
dashboard.py — Read-only audit log visualization.

Displays governance operation history from audit_log.json.
No cryptographic logic lives here. This module only reads the audit log.

Run with: streamlit run spy/dashboard.py
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import streamlit as st

try:
    from .audit_logger import AUDIT_LOG_FILE
except ImportError:
    # streamlit run adds spy/ to sys.path and executes as a top-level script;
    # relative imports are unavailable in that mode.
    from audit_logger import AUDIT_LOG_FILE  # type: ignore[no-redef]

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOG_FILE = AUDIT_LOG_FILE
MAX_ROWS = 200  # cap on log lines read

st.set_page_config(
    page_title="Encryption Governance Dashboard",
    page_icon="🔒",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def _load_events(path: Path, limit: int = MAX_ROWS) -> list[dict]:
    """Read and parse the most recent `limit` events from the JSON log file."""
    if not path.exists():
        return []
    events = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        for line in lines[-limit:]:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    except OSError:
        return []
    return events


# ---------------------------------------------------------------------------
# Page layout
# ---------------------------------------------------------------------------

st.title("Encryption Governance Dashboard")
st.caption("Read-only view of governance operations. Refresh the page to reload the log.")

_secret = os.environ.get("DASHBOARD_SECRET", "")
if _secret:
    entered = st.text_input("Dashboard password", type="password")
    if entered != _secret:
        st.stop()

events = _load_events(LOG_FILE)

if not events:
    st.info("No audit events found. Run the governance pipeline or CLI to generate log entries.")
    st.stop()

# ---------------------------------------------------------------------------
# Summary metrics
# ---------------------------------------------------------------------------

total = len(events)
successes = sum(1 for e in events if e.get("result") == "SUCCESS")
denials = sum(1 for e in events if e.get("result") == "DENIED")
errors = sum(1 for e in events if e.get("result") == "ERROR")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Operations", total)
col2.metric("Successful", successes)
col3.metric("Denied", denials)
col4.metric("Errors", errors)

st.divider()

# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------

st.subheader("Result Distribution")
result_data = {k: v for k, v in {"SUCCESS": successes, "DENIED": denials, "ERROR": errors}.items() if v > 0}
if result_data:
    st.bar_chart(result_data)

st.divider()

# ---------------------------------------------------------------------------
# Recent operations table
# ---------------------------------------------------------------------------

st.subheader("Recent Operations")

DISPLAY_COLUMNS = ["timestamp", "username", "role", "action", "classification", "key_id", "result"]

rows = []
for e in reversed(events):  # most recent first
    rows.append({col: e.get(col, "") for col in DISPLAY_COLUMNS})

st.dataframe(
    rows,
    use_container_width=True,
    column_config={
        "timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
        "username": st.column_config.TextColumn("User"),
        "role": st.column_config.TextColumn("Role"),
        "action": st.column_config.TextColumn("Action"),
        "classification": st.column_config.TextColumn("Classification"),
        "key_id": st.column_config.TextColumn("Key ID"),
        "result": st.column_config.TextColumn("Result"),
    },
    hide_index=True,
)

st.caption(f"Showing {min(len(rows), MAX_ROWS)} most recent events from {LOG_FILE.name}")
