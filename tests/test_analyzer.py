from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from synapseaudit.analyzer import analyze_file
from synapseaudit.cli import main, render_text


PROJECT_ROOT = Path(__file__).resolve().parents[1]
VULNERABLE_FIXTURE = PROJECT_ROOT / "fixtures" / "compose.vulnerable.yml"
REMEDIATED_FIXTURE = PROJECT_ROOT / "fixtures" / "compose.remediated.yml"


class AnalyzerTests(unittest.TestCase):
    def test_privileged_container_check_finds_the_fixture_service(self) -> None:
        report = analyze_file(VULNERABLE_FIXTURE)

        privileged = [finding for finding in report.findings if finding.id == "PRIVILEGED_CONTAINER"]
        self.assertEqual(len(privileged), 1)
        self.assertEqual(privileged[0].service, "audit-demo")
        self.assertEqual(privileged[0].severity, "high")

    def test_writable_bind_check_finds_the_fixture_mount(self) -> None:
        report = analyze_file(VULNERABLE_FIXTURE)

        writable = [finding for finding in report.findings if finding.id == "WRITABLE_HOST_BIND"]
        self.assertEqual(len(writable), 1)
        self.assertIn("./fixture-data", writable[0].evidence)

    def test_findings_combine_into_a_bounded_attack_path(self) -> None:
        report = analyze_file(VULNERABLE_FIXTURE)

        self.assertEqual(len(report.attack_paths), 1)
        path = report.attack_paths[0]
        self.assertEqual(path.id, "PRIVILEGE_TO_SHARED-DATA")
        self.assertEqual(path.service, "audit-demo")
        self.assertIn("no command or container action is executed", path.impact)

    def test_remediated_fixture_has_no_supported_findings_or_paths(self) -> None:
        report = analyze_file(REMEDIATED_FIXTURE)

        self.assertEqual(report.findings, ())
        self.assertEqual(report.attack_paths, ())

    def test_json_output_is_machine_readable(self) -> None:
        report = analyze_file(VULNERABLE_FIXTURE)

        payload = json.loads(report.to_json())
        self.assertEqual(payload["findings"][0]["id"], "PRIVILEGED_CONTAINER")
        self.assertEqual(payload["attack_paths"][0]["service"], "audit-demo")

    def test_text_cli_output_reports_findings_and_paths(self) -> None:
        report = analyze_file(VULNERABLE_FIXTURE)
        with patch("builtins.print") as print_mock:
            exit_code = main([str(VULNERABLE_FIXTURE)])

        self.assertEqual(exit_code, 0)
        output = print_mock.call_args.args[0]
        self.assertEqual(output, render_text(report))
        self.assertIn("PRIVILEGED_CONTAINER", output)
        self.assertIn("PRIVILEGE_TO_SHARED-DATA", output)


if __name__ == "__main__":
    unittest.main()
