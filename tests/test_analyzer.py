from __future__ import annotations

import json
import multiprocessing
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from synapseaudit.analyzer import (
    ComposeAnalysisLimitError,
    ComposeAnalysisLimits,
    ComposeAnalysisTimeoutError,
    ComposeConfigError,
    analyze_compose,
    analyze_compose_bytes,
    analyze_compose_bytes_bounded,
    analyze_file,
    load_compose,
)
from synapseaudit.cli import main, render_text


PROJECT_ROOT = Path(__file__).resolve().parents[1]
VULNERABLE_FIXTURE = PROJECT_ROOT / "fixtures" / "compose.vulnerable.yml"
REMEDIATED_FIXTURE = PROJECT_ROOT / "fixtures" / "compose.remediated.yml"


def _sleeping_analysis_worker(connection, content, source_file, limits) -> None:
    time.sleep(1)


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

    def test_dangerous_capability_check_finds_high_risk_capability(self) -> None:
        report = analyze_file(VULNERABLE_FIXTURE)

        dangerous = [finding for finding in report.findings if finding.id == "DANGEROUS_CAPABILITY"]
        self.assertEqual(len(dangerous), 1)
        self.assertEqual(dangerous[0].service, "audit-demo")
        self.assertEqual(dangerous[0].severity, "high")
        self.assertIn("SYS_ADMIN", dangerous[0].evidence)

    def test_safe_capabilities_and_absent_cap_add_are_not_findings(self) -> None:
        report = analyze_compose(
            {
                "services": {
                    "safe-capability": {"cap_add": ["CHOWN"]},
                    "no-capability": {"image": "example:local"},
                }
            }
        )

        self.assertEqual(report.findings, ())
        self.assertEqual(report.attack_paths, ())

    def test_capability_names_are_normalized_and_deduplicated(self) -> None:
        report = analyze_compose(
            {"services": {"worker": {"cap_add": ["cap_sys_admin", "NET_ADMIN", "SYS_ADMIN"]}}}
        )

        dangerous = [finding for finding in report.findings if finding.id == "DANGEROUS_CAPABILITY"]
        self.assertEqual(len(dangerous), 1)
        self.assertEqual(dangerous[0].evidence, "services.worker.cap_add includes SYS_ADMIN, NET_ADMIN")

    def test_exposed_port_check_finds_short_all_interface_mapping(self) -> None:
        report = analyze_file(VULNERABLE_FIXTURE)

        exposed = [finding for finding in report.findings if finding.id == "EXPOSED_SERVICE_PORT"]
        self.assertEqual(len(exposed), 1)
        self.assertEqual(exposed[0].service, "audit-demo")
        self.assertEqual(exposed[0].severity, "medium")
        self.assertIn("host port 8080", exposed[0].evidence)
        self.assertIn("all host interfaces", exposed[0].evidence)

    def test_exposed_port_check_supports_long_loopback_mapping(self) -> None:
        report = analyze_compose(
            {
                "services": {
                    "web": {
                        "ports": [
                            {
                                "target": 80,
                                "published": "8080",
                                "host_ip": "127.0.0.1",
                                "protocol": "tcp",
                            }
                        ]
                    }
                }
            }
        )

        exposed = [finding for finding in report.findings if finding.id == "EXPOSED_SERVICE_PORT"]
        self.assertEqual(len(exposed), 1)
        self.assertIn("loopback only", exposed[0].evidence)

    def test_container_only_port_mappings_are_not_findings(self) -> None:
        report = analyze_compose(
            {
                "services": {
                    "web": {"ports": ["80", {"target": 8080}]},
                }
            }
        )

        self.assertEqual(report.findings, ())
        self.assertEqual(report.attack_paths, ())

    def test_long_syntax_read_only_bind_and_named_volume_are_not_findings(self) -> None:
        report = analyze_compose(
            {
                "services": {
                    "safe": {
                        "privileged": False,
                        "volumes": [
                            {"type": "bind", "source": "./fixture-data", "target": "/app/data", "read_only": True},
                            "named-data:/app/cache:rw",
                        ],
                    }
                }
            }
        )

        self.assertEqual(report.findings, ())
        self.assertEqual(report.attack_paths, ())

    def test_findings_combine_into_a_bounded_attack_path(self) -> None:
        report = analyze_file(VULNERABLE_FIXTURE)

        self.assertEqual(len(report.findings), 4)
        self.assertEqual(len(report.attack_paths), 1)
        for finding in report.findings:
            self.assertTrue(finding.explanation)
            self.assertTrue(finding.impact)
            self.assertTrue(finding.evidence)
            self.assertTrue(finding.remediation)
            self.assertTrue(finding.limitations)
        path = report.attack_paths[0]
        self.assertEqual(path.id, "PRIVILEGE_TO_SHARED-DATA")
        self.assertEqual(path.service, "audit-demo")
        self.assertEqual(path.classification, "deterministic_hypothetical_correlation")
        self.assertIn("no command or container action is executed", path.impact)
        self.assertIn("not proof of exploitation", path.limitations)

    def test_remediated_fixture_has_no_supported_findings_or_paths(self) -> None:
        report = analyze_file(REMEDIATED_FIXTURE)

        self.assertEqual(len(report.findings), 0)
        self.assertEqual(len(report.attack_paths), 0)
        self.assertEqual(report.findings, ())
        self.assertEqual(report.attack_paths, ())

    def test_json_output_is_machine_readable(self) -> None:
        report = analyze_file(VULNERABLE_FIXTURE)

        payload = json.loads(report.to_json())
        self.assertEqual(payload["findings"][0]["id"], "PRIVILEGED_CONTAINER")
        self.assertEqual(payload["attack_paths"][0]["service"], "audit-demo")

    def test_in_memory_vulnerable_yaml_matches_file_analysis(self) -> None:
        file_report = analyze_file(VULNERABLE_FIXTURE)
        memory_report = analyze_compose_bytes(VULNERABLE_FIXTURE.read_bytes())

        self.assertEqual(memory_report, file_report)
        self.assertEqual(len(memory_report.findings), 4)
        self.assertEqual(len(memory_report.attack_paths), 1)

    def test_in_memory_remediated_yaml_has_no_findings_or_paths(self) -> None:
        report = analyze_compose_bytes(REMEDIATED_FIXTURE.read_bytes())

        self.assertEqual(report.findings, ())
        self.assertEqual(report.attack_paths, ())

    def test_in_memory_yaml_rejects_invalid_utf8_and_empty_content(self) -> None:
        with self.assertRaises(ComposeConfigError):
            analyze_compose_bytes(b"\xff\xfe")
        with self.assertRaises(ComposeConfigError):
            analyze_compose_bytes(b"")

    def test_repository_source_metadata_uses_yaml_marks_without_text_search(self) -> None:
        content = b"""services:
  web:
    privileged: true
    cap_add:
      - SYS_ADMIN
    ports:
      - \"8080:80\"
    volumes:
      - ./data:/data:rw
"""

        report = analyze_compose_bytes(content, source_file="nested/compose.yml")

        locations = {finding.id: (finding.file_path, finding.line_start, finding.line_end) for finding in report.findings}
        self.assertEqual(locations["PRIVILEGED_CONTAINER"], ("nested/compose.yml", 3, 3))
        self.assertEqual(locations["DANGEROUS_CAPABILITY"], ("nested/compose.yml", 5, 5))
        self.assertEqual(locations["EXPOSED_SERVICE_PORT"], ("nested/compose.yml", 7, 7))
        self.assertEqual(locations["WRITABLE_HOST_BIND"], ("nested/compose.yml", 9, 9))

    def test_bounded_analysis_terminates_a_slow_worker(self) -> None:
        before = {process.pid for process in multiprocessing.active_children()}
        with self.assertRaises(ComposeAnalysisTimeoutError):
            analyze_compose_bytes_bounded(
                b"services:\n  web:\n    image: safe\n",
                limits=ComposeAnalysisLimits(max_duration_seconds=1),
                timeout_seconds=0.05,
                worker=_sleeping_analysis_worker,
            )
        time.sleep(0.05)
        self.assertEqual(before, {process.pid for process in multiprocessing.active_children()})

    def test_bounded_analysis_rejects_structurally_deep_yaml(self) -> None:
        content = b"services:\n  web:\n    environment:\n      nested:\n        deeper:\n          value: true\n"
        with self.assertRaises(ComposeAnalysisLimitError):
            analyze_compose_bytes_bounded(
                content,
                limits=ComposeAnalysisLimits(max_yaml_depth=3),
                timeout_seconds=1,
            )

    def test_text_cli_output_reports_findings_and_paths(self) -> None:
        report = analyze_file(VULNERABLE_FIXTURE)
        with patch("builtins.print") as print_mock:
            exit_code = main([str(VULNERABLE_FIXTURE)])

        self.assertEqual(exit_code, 0)
        output = print_mock.call_args.args[0]
        self.assertEqual(output, render_text(report))
        self.assertIn("PRIVILEGED_CONTAINER", output)
        self.assertIn("PRIVILEGE_TO_SHARED-DATA", output)
        self.assertIn("Explanation:", output)
        self.assertIn("Limitations:", output)

    def test_malformed_yaml_is_rejected_as_a_compose_error(self) -> None:
        malformed = PROJECT_ROOT / "tests" / "malformed-compose.yml"
        malformed.write_text("services:\n  broken: [\n", encoding="utf-8")
        self.addCleanup(malformed.unlink)

        with self.assertRaises(ComposeConfigError):
            load_compose(malformed)

    def test_malformed_service_is_rejected_instead_of_reported_clean(self) -> None:
        with self.assertRaises(ComposeConfigError):
            analyze_compose({"services": {"broken": "not a service mapping"}})

    def test_invalid_restart_type_is_rejected_instead_of_reported_clean(self) -> None:
        with self.assertRaises(ComposeConfigError):
            analyze_compose({"services": {"broken": {"restart": []}}})

    def test_malformed_volume_list_is_rejected_instead_of_reported_clean(self) -> None:
        with self.assertRaises(ComposeConfigError):
            analyze_compose({"services": {"broken": {"volumes": "./data:/data"}}})

    def test_malformed_volume_entry_is_rejected_instead_of_reported_clean(self) -> None:
        with self.assertRaises(ComposeConfigError):
            analyze_compose({"services": {"broken": {"volumes": [123]}}})

    def test_malformed_short_volume_is_rejected_instead_of_reported_clean(self) -> None:
        with self.assertRaises(ComposeConfigError):
            analyze_compose({"services": {"broken": {"volumes": ["./fixture-data"]}}})

    def test_missing_bind_fields_are_rejected_instead_of_missed(self) -> None:
        with self.assertRaises(ComposeConfigError):
            analyze_compose(
                {
                    "services": {
                        "broken": {"volumes": [{"type": "bind", "source": "./fixture-data"}]}
                    }
                }
            )

    def test_malformed_privileged_value_is_rejected_instead_of_missed(self) -> None:
        with self.assertRaises(ComposeConfigError):
            analyze_compose({"services": {"broken": {"privileged": "true"}}})

    def test_malformed_capability_list_is_rejected_instead_of_missed(self) -> None:
        with self.assertRaises(ComposeConfigError):
            analyze_compose({"services": {"broken": {"cap_add": "SYS_ADMIN"}}})

    def test_malformed_capability_entry_is_rejected_instead_of_missed(self) -> None:
        with self.assertRaises(ComposeConfigError):
            analyze_compose({"services": {"broken": {"cap_add": ["SYS_ADMIN", 123]}}})

    def test_malformed_ports_list_is_rejected_instead_of_missed(self) -> None:
        with self.assertRaises(ComposeConfigError):
            analyze_compose({"services": {"broken": {"ports": "8080:80"}}})

    def test_malformed_port_mapping_is_rejected_instead_of_missed(self) -> None:
        with self.assertRaises(ComposeConfigError):
            analyze_compose(
                {
                    "services": {
                        "broken": {
                            "ports": [
                                {"target": 80, "published": "8080", "host_ip": "not-an-ip"}
                            ]
                        }
                    }
                }
            )

    def test_cli_returns_error_for_malformed_compose(self) -> None:
        malformed = PROJECT_ROOT / "tests" / "malformed-compose.yml"
        malformed.write_text("services:\n  broken: [\n", encoding="utf-8")
        self.addCleanup(malformed.unlink)

        with patch("builtins.print") as print_mock:
            exit_code = main([str(malformed)])

        self.assertEqual(exit_code, 2)
        self.assertIn("error: Invalid YAML", print_mock.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
