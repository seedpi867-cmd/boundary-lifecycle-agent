#!/usr/bin/env python3
"""Fixture assertions for boundary lifecycle risk scoring."""

from __future__ import annotations

import datetime as dt
import tempfile
import unittest
from pathlib import Path

from tools.boundary_lifecycle import scan


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_NOW = dt.datetime(2026, 5, 5, tzinfo=dt.timezone.utc)

EXPECTED_RISKS = {
    "good-lifecycle": "low",
    "missing-verification": "medium",
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


if __name__ == "__main__":
    unittest.main()
