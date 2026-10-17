"""Command-line interface for SynapseAudit."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from .analyzer import AnalysisReport, ComposeConfigError, analyze_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="synapseaudit",
        description="Analyze Docker Compose configuration without running Docker.",
    )
    parser.add_argument("compose_file", type=Path, help="path to a Compose YAML file")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="output_format",
        help="output format (default: text)",
    )
    return parser


def render_text(report: AnalysisReport) -> str:
    lines = [f"Findings: {len(report.findings)}"]
    for finding in report.findings:
        lines.extend(
            (
                f"- [{finding.severity.upper()}] {finding.id} ({finding.service})",
                f"  {finding.title}",
                f"  Explanation: {finding.explanation}",
                f"  Impact: {finding.impact}",
                f"  Evidence: {finding.evidence}",
                f"  Remediation: {finding.remediation}",
                f"  Limitations: {finding.limitations}",
            )
        )

    lines.append(f"Attack paths: {len(report.attack_paths)}")
    for path in report.attack_paths:
        lines.append(f"- {path.id} ({path.service}): {path.title}")
        lines.append(f"  Classification: {path.classification}")
        for step_number, step in enumerate(path.steps, start=1):
            lines.append(f"  {step_number}. {step}")
        lines.append(f"  Impact: {path.impact}")
        lines.append(f"  Remediation: {path.remediation}")
        lines.append(f"  Limitations: {path.limitations}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = analyze_file(args.compose_file)
    except ComposeConfigError as exc:
        print(f"error: {exc}")
        return 2

    if args.output_format == "json":
        print(report.to_json())
    else:
        print(render_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
