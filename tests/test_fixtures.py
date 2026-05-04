#!/usr/bin/env python3
"""Fixture assertions for boundary lifecycle risk scoring."""

from __future__ import annotations

import datetime as dt
import tempfile
import unittest
from pathlib import Path

from tools.boundary_lifecycle import contains_collapsed_secret, scan


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_NOW = dt.datetime(2026, 5, 5, tzinfo=dt.timezone.utc)

EXPECTED_RISKS = {
    "good-lifecycle": "low",
    "missing-verification": "medium",
    "manual-recovery-needed": "low",
    "stale-approval": "high",
    "collapsed-credential": "critical",
}


class FixtureRiskTests(unittest.TestCase):
    def test_sample_risk_levels_stay_stable(self) -> None:
        for fixture, expected_risk in EXPECTED_RISKS.items():
            with self.subTest(fixture=fixture):
                with tempfile.TemporaryDirectory() as tmp:
                    result = scan(ROOT / "samples" / fixture, Path(tmp), FIXTURE_NOW)
                pathway = result["pathways"][0]

                self.assertEqual(pathway["pathway_id"], fixture)
                self.assertEqual(pathway["risk"], expected_risk)
                self.assertEqual(result["risk_counts"], {expected_risk: 1})

    def test_manual_recovery_followup_is_thin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = scan(ROOT / "samples" / "manual-recovery-needed", Path(tmp), FIXTURE_NOW)
        recovery = result["pathways"][0]["stages"]["recovery"]

        self.assertEqual(result["pathways"][0]["risk"], "low")
        self.assertEqual(recovery["status"], "thin")
        self.assertTrue(any("manual follow-up" in note for note in recovery["notes"]))

    def test_credential_labels_are_not_secret_values(self) -> None:
        text = "- requested_secret: github-token\n- target: github\n"

        self.assertFalse(contains_collapsed_secret("output/custody-report.md", text))

    def test_real_secret_shapes_still_collapse_boundary(self) -> None:
        text = 'TOKEN = "sk_live_example_secret_value_123456"\n'

        self.assertTrue(contains_collapsed_secret("tools/post.py", text))


if __name__ == "__main__":
    unittest.main()
