from pathlib import Path

import pandas as pd


DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "incidents.csv"
REQUIRED_COLUMNS = {
    "incident_id",
    "detected_at",
    "triaged_at",
    "contained_at",
    "resolved_at",
    "title",
    "severity",
    "status",
    "category",
    "source",
    "owner",
    "summary",
    "assets",
    "accounts",
    "iocs",
    "asset_criticality",
    "confidence",
    "data_exfiltration",
    "persistence_detected",
    "ransomware_indicator",
    "regulated_data",
}
SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
BOOLEAN_COLUMNS = (
    "data_exfiltration",
    "persistence_detected",
    "ransomware_indicator",
    "regulated_data",
)


def load_incidents(path: str | Path = DATA_PATH) -> pd.DataFrame:
    """Load and validate the workbench's incident CSV."""
    csv_path = Path(path)
    if not csv_path.is_file():
        raise FileNotFoundError(f"Incident dataset not found: {csv_path}")

    try:
        incidents = pd.read_csv(csv_path)
    except (OSError, pd.errors.ParserError, UnicodeDecodeError) as exc:
        raise ValueError(f"Could not read incident dataset: {exc}") from exc

    missing = sorted(REQUIRED_COLUMNS.difference(incidents.columns))
    if missing:
        raise ValueError(f"Incident dataset is missing required columns: {', '.join(missing)}")
    if incidents.empty:
        raise ValueError("Incident dataset contains no incident rows.")

    incidents = incidents.copy()
    incidents["incident_id"] = incidents["incident_id"].astype("string").str.strip()
    if incidents["incident_id"].isna().any() or incidents["incident_id"].eq("").any():
        raise ValueError("Every incident must have a non-empty incident_id.")
    if incidents["incident_id"].duplicated().any():
        duplicates = incidents.loc[incidents["incident_id"].duplicated(), "incident_id"].tolist()
        raise ValueError(f"Incident IDs must be unique; duplicates: {', '.join(duplicates)}")

    incidents["severity"] = incidents["severity"].astype("string").str.strip().str.title()
    invalid_severities = sorted(set(incidents["severity"].dropna()) - set(SEVERITIES))
    if invalid_severities:
        raise ValueError(f"Unsupported incident severity values: {', '.join(invalid_severities)}")
    if incidents["severity"].isna().any():
        raise ValueError("Every incident must have a severity.")

    for column in ("detected_at", "triaged_at", "contained_at", "resolved_at"):
        raw_values = incidents[column]
        incidents[column] = pd.to_datetime(raw_values, format="ISO8601", errors="coerce", utc=True)
        malformed = incidents[column].isna() & raw_values.notna() & raw_values.astype(str).str.strip().ne("")
        if malformed.any():
            raise ValueError(f"Incident dataset contains an invalid timestamp in {column}.")
    if incidents["detected_at"].isna().any():
        raise ValueError("Every incident must have a valid detected_at timestamp.")

    for column in BOOLEAN_COLUMNS:
        values = incidents[column].astype("string").str.strip().str.lower()
        invalid = ~values.isin({"true", "false", "1", "0", "yes", "no"})
        if invalid.any():
            raise ValueError(f"Incident dataset contains invalid boolean values in {column}.")
        incidents[column] = values.isin({"true", "1", "yes"})

    text_columns = ("title", "status", "category", "source", "owner", "summary", "assets", "accounts", "iocs")
    for column in text_columns:
        incidents[column] = incidents[column].astype("string").str.strip()
        if incidents[column].isna().any() or incidents[column].eq("").any():
            raise ValueError(f"Incident dataset contains an empty required value in {column}.")

    for previous, current in (
        ("detected_at", "triaged_at"),
        ("triaged_at", "contained_at"),
        ("contained_at", "resolved_at"),
    ):
        out_of_order = (
            incidents[previous].notna()
            & incidents[current].notna()
            & (incidents[current] < incidents[previous])
        )
        if out_of_order.any():
            raise ValueError(f"Incident timestamps are out of order: {current} precedes {previous}.")

    incidents["confidence"] = pd.to_numeric(incidents["confidence"], errors="coerce")
    if incidents["confidence"].isna().any() or not incidents["confidence"].between(0, 100).all():
        raise ValueError("Incident confidence must be a number between 0 and 100.")

    incidents["asset_criticality"] = incidents["asset_criticality"].astype("string").str.strip().str.title()
    if not incidents["asset_criticality"].isin({"Critical", "High", "Medium", "Low"}).all():
        raise ValueError("Asset criticality must be Critical, High, Medium, or Low.")

    return incidents.sort_values("detected_at", ascending=False).reset_index(drop=True)
