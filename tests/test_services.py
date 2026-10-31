import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import pandas as pd

from ir_workbench.data import DATA_PATH, load_incidents
from ir_workbench.reports import build_incident_report
from ir_workbench.services import (
    build_timeline,
    recommend_escalation,
    scope_incident,
    triage_incidents,
    verify_sha256,
)


class IncidentServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.incidents = load_incidents()

    def test_synthetic_dataset_loads_with_unique_ids(self):
        self.assertGreaterEqual(len(self.incidents), 10)
        self.assertTrue(self.incidents["incident_id"].is_unique)
        self.assertTrue(self.incidents["detected_at"].notna().all())

    def test_dataset_rejects_malformed_timestamps(self):
        source = pd.read_csv(DATA_PATH)
        source.loc[0, "detected_at"] = "not-a-timestamp"
        with TemporaryDirectory() as directory:
            path = Path(directory) / "incidents.csv"
            source.to_csv(path, index=False)
            with self.assertRaisesRegex(ValueError, "invalid timestamp"):
                load_incidents(path)

    def test_triage_search_is_literal_and_filters_severity(self):
        matches = triage_incidents(self.incidents, query="PowerShell", severities=["Critical"])
        self.assertEqual(matches["incident_id"].tolist(), ["IR-2026-1042"])
        self.assertTrue(triage_incidents(self.incidents, query="[", severities=["Critical"]).empty)

    def test_timeline_contains_lifecycle_events_in_time_order(self):
        timeline = build_timeline(self.incidents)
        self.assertIn("Alert detected", timeline["event"].values)
        self.assertTrue(timeline["event_time"].is_monotonic_increasing)
        self.assertEqual(len(timeline), sum(self.incidents[column].notna().sum() for column in (
            "detected_at", "triaged_at", "contained_at", "resolved_at"
        )))

    def test_scoping_finds_incidents_sharing_an_asset(self):
        scope = scope_incident(self.incidents, "IR-2026-1042")
        self.assertIn("fin-fs-02", scope["assets"])
        self.assertIn("IR-2026-1034", scope["related_incidents"]["incident_id"].tolist())

    def test_escalation_recommendation_is_educational(self):
        incident = self.incidents.loc[self.incidents["incident_id"] == "IR-2026-1042"].iloc[0]
        recommendation = recommend_escalation(incident)
        self.assertEqual(recommendation["level"], "Priority CSIRT coordination")
        self.assertIn("does not contact", recommendation["notice"])

    def test_evidence_digest_matches_expected_sha256(self):
        content = b"synthetic evidence"
        result = verify_sha256(content)
        self.assertEqual(len(result["sha256"]), 64)
        self.assertIsNone(result["matches"])
        verified = verify_sha256(content, result["sha256"])
        self.assertTrue(verified["matches"])
        mismatched = verify_sha256(content, "0" * 64)
        self.assertFalse(mismatched["matches"])

    def test_bundled_synthetic_evidence_matches_its_manifest(self):
        evidence = DATA_PATH.parent / "evidence" / "SYNTHETIC_auth_events.txt"
        expected = evidence.with_suffix(".sha256").read_text(encoding="utf-8").split()[0]
        self.assertTrue(verify_sha256(evidence.read_bytes(), expected)["matches"])

    def test_invalid_expected_hash_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "64 hexadecimal"):
            verify_sha256(b"evidence", "not-a-hash")

    def test_report_contains_synthetic_notice_and_case_summary(self):
        report = build_incident_report(self.incidents, "IR-2026-1042")
        self.assertIn("Synthetic educational data", report)
        self.assertIn("Suspicious PowerShell", report)

    def test_scope_rejects_unknown_incident(self):
        with self.assertRaisesRegex(ValueError, "was not found"):
            scope_incident(self.incidents, "not-a-case")


if __name__ == "__main__":
    unittest.main()
