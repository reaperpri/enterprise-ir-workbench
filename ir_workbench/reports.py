from collections.abc import Mapping

import pandas as pd

from ir_workbench.services import scope_incident


def build_incident_report(incidents: pd.DataFrame, incident_id: str) -> str:
    """Create a downloadable, self-contained Markdown investigation summary."""
    matches = incidents.loc[incidents["incident_id"].astype(str) == str(incident_id)]
    if matches.empty:
        raise ValueError(f"Incident {incident_id!r} was not found.")
    incident: Mapping = matches.iloc[0].to_dict()
    scope = scope_incident(incidents, incident_id)

    timestamp = incident["detected_at"]
    detected = timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp)
    related = scope["related_incidents"]
    related_text = (
        "\n".join(
            f"- `{row.incident_id}` ({row.severity}, {row.status}) — {row.matched_entities}"
            for row in related.itertuples(index=False)
        )
        if not related.empty
        else "- No related incidents identified in this synthetic dataset."
    )
    entity_lines = []
    for label, key in (("Assets", "assets"), ("Accounts", "accounts"), ("Indicators", "iocs")):
        values = scope[key]
        entity_lines.append(f"- **{label}:** {', '.join(values) if values else 'None recorded'}")

    return f"""# Incident Investigation Report — {incident['incident_id']}

> **Synthetic educational data.** This report is not an operational incident record and does not authorize or perform security response actions.

## Overview

- **Title:** {incident['title']}
- **Severity / status:** {incident['severity']} / {incident['status']}
- **Category:** {incident['category']}
- **Detection time (UTC):** {detected}
- **Source:** {incident['source']}
- **Assigned analyst:** {incident['owner']}
- **Confidence:** {incident['confidence']}%

## Summary

{incident['summary']}

## Scope

{chr(10).join(entity_lines)}

### Related incidents

{related_text}

## Impact indicators

- Possible data exfiltration: {'Yes' if incident['data_exfiltration'] else 'No'}
- Persistence indicator: {'Yes' if incident['persistence_detected'] else 'No'}
- Ransomware indicator: {'Yes' if incident['ransomware_indicator'] else 'No'}
- Regulated data may be in scope: {'Yes' if incident['regulated_data'] else 'No'}

## CSIRT coordination

Review the dashboard's educational escalation recommendation alongside authorized organizational procedures. No notification or response action was performed by this report.

## Evidence integrity

No evidence files are embedded in this report. Record evidence hashes separately using the Evidence Integrity view and follow approved evidence-handling procedures.
"""
