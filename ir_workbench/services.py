import hashlib
import re
from collections.abc import Mapping

import pandas as pd

from ir_workbench.data import SEVERITIES

_SEARCH_COLUMNS = ("incident_id", "title", "summary", "category", "source", "owner", "assets", "accounts", "iocs")
_HASH_PATTERN = re.compile(r"^[A-Fa-f0-9]{64}$")


def triage_incidents(
    incidents: pd.DataFrame,
    query: str = "",
    severities: tuple[str, ...] | list[str] | None = None,
    statuses: tuple[str, ...] | list[str] | None = None,
    start_date=None,
    end_date=None,
) -> pd.DataFrame:
    """Filter incidents using literal search, severity, status, and detection date."""
    if "incident_id" not in incidents or "detected_at" not in incidents:
        raise ValueError("Incident data must include incident_id and detected_at columns.")
    if severities is not None and not set(severities).issubset(SEVERITIES):
        raise ValueError("Severity filter contains an unsupported value.")

    mask = pd.Series(True, index=incidents.index)
    if query.strip():
        searchable = [column for column in _SEARCH_COLUMNS if column in incidents.columns]
        text_match = incidents[searchable].fillna("").astype(str).agg(" ".join, axis=1)
        mask &= text_match.str.contains(query.strip(), case=False, regex=False)
    if severities:
        mask &= incidents["severity"].isin(severities)
    if statuses:
        mask &= incidents["status"].isin(statuses)
    if start_date is not None:
        mask &= incidents["detected_at"].dt.date >= start_date
    if end_date is not None:
        mask &= incidents["detected_at"].dt.date <= end_date
    return incidents.loc[mask].sort_values("detected_at", ascending=False).copy()


def build_timeline(incidents: pd.DataFrame) -> pd.DataFrame:
    """Expand incident lifecycle timestamps into chartable timeline events."""
    event_columns = (
        ("detected_at", "Alert detected"),
        ("triaged_at", "Triage started"),
        ("contained_at", "Contained"),
        ("resolved_at", "Resolved"),
    )
    required = {"incident_id", "severity", *(column for column, _ in event_columns)}
    if not required.issubset(incidents.columns):
        raise ValueError("Incident data is missing columns required to build the timeline.")

    events = []
    for row in incidents.itertuples(index=False):
        record = row._asdict()
        for column, event_name in event_columns:
            timestamp = record[column]
            if pd.notna(timestamp):
                events.append(
                    {
                        "incident_id": record["incident_id"],
                        "severity": record["severity"],
                        "event": event_name,
                        "event_time": timestamp,
                    }
                )
    return pd.DataFrame(events, columns=("incident_id", "severity", "event", "event_time")).sort_values(
        "event_time"
    ).reset_index(drop=True)


def _split_entities(value: object) -> set[str]:
    if value is None or pd.isna(value):
        return set()
    return {item.strip().casefold() for item in str(value).split("|") if item.strip()}


def scope_incident(incidents: pd.DataFrame, incident_id: str) -> dict:
    """Find incidents sharing an asset, account, or indicator with the selected case."""
    matches = incidents.loc[incidents["incident_id"].astype(str) == str(incident_id)]
    if matches.empty:
        raise ValueError(f"Incident {incident_id!r} was not found.")
    incident = matches.iloc[0]
    entities = {
        column: _split_entities(incident[column])
        for column in ("assets", "accounts", "iocs")
        if column in incidents.columns
    }

    related = []
    for _, candidate in incidents.iterrows():
        matched_entities = []
        for column, selected_values in entities.items():
            overlap = selected_values.intersection(_split_entities(candidate.get(column)))
            if overlap:
                matched_entities.extend(f"{column[:-1]}: {value}" for value in sorted(overlap))
        if matched_entities:
            related.append(
                {
                    "incident_id": candidate["incident_id"],
                    "title": candidate.get("title", ""),
                    "severity": candidate.get("severity", ""),
                    "status": candidate.get("status", ""),
                    "matched_entities": ", ".join(sorted(set(matched_entities))),
                }
            )
    related_df = pd.DataFrame(
        related, columns=("incident_id", "title", "severity", "status", "matched_entities")
    ).sort_values("incident_id").reset_index(drop=True)

    return {
        "incident_id": str(incident_id),
        "assets": sorted(_split_entities(incident.get("assets"))),
        "accounts": sorted(_split_entities(incident.get("accounts"))),
        "iocs": sorted(_split_entities(incident.get("iocs"))),
        "related_incidents": related_df,
    }


def recommend_escalation(incident: Mapping) -> dict:
    """Return educational CSIRT coordination guidance based on incident attributes."""
    severity = str(incident.get("severity", "")).title()
    if severity not in SEVERITIES:
        raise ValueError(f"Unsupported severity for escalation recommendation: {severity!r}")

    critical_asset = str(incident.get("asset_criticality", "")).title() == "Critical"
    high_impact = any(
        bool(incident.get(field, False))
        for field in ("data_exfiltration", "persistence_detected", "ransomware_indicator", "regulated_data")
    )
    if severity == "Critical" or high_impact or critical_asset:
        level = "Priority CSIRT coordination"
        rationale = "Severity, potential impact, or asset criticality warrants prompt cross-functional review."
    elif severity == "High":
        level = "Expedited CSIRT review"
        rationale = "High-severity activity should receive timely coordinated investigation."
    else:
        level = "Standard investigation"
        rationale = "Continue structured triage and reassess if scope or impact increases."

    return {
        "level": level,
        "rationale": rationale,
        "indicators": [
            label
            for field, label in (
                ("data_exfiltration", "Possible data exfiltration"),
                ("persistence_detected", "Persistence indicator"),
                ("ransomware_indicator", "Ransomware indicator"),
                ("regulated_data", "Regulated data may be in scope"),
            )
            if bool(incident.get(field, False))
        ],
        "review_checklist": [
            "Validate the alert and preserve relevant evidence using approved internal procedures.",
            "Confirm affected assets, accounts, time window, and business impact with authorized owners.",
            "Coordinate next steps through the organization's established incident response process.",
        ],
        "notice": "Educational recommendation only; this workbench does not contact a CSIRT or perform response actions.",
    }


def sha256_bytes(content: bytes) -> str:
    """Compute a SHA-256 digest for uploaded or sample evidence bytes."""
    if not isinstance(content, bytes):
        raise TypeError("Evidence content must be bytes.")
    if not content:
        raise ValueError("Evidence file is empty; provide a non-empty file to hash.")
    return hashlib.sha256(content).hexdigest()


def verify_sha256(content: bytes, expected_hash: str | None = None) -> dict:
    """Hash evidence and, when provided, compare it with a validated expected digest."""
    actual_hash = sha256_bytes(content)
    normalized_expected = (expected_hash or "").strip().lower()
    if not normalized_expected:
        return {"sha256": actual_hash, "expected_sha256": None, "matches": None}
    if not _HASH_PATTERN.fullmatch(normalized_expected):
        raise ValueError("Expected SHA-256 must contain exactly 64 hexadecimal characters.")
    return {
        "sha256": actual_hash,
        "expected_sha256": normalized_expected,
        "matches": actual_hash == normalized_expected,
    }
