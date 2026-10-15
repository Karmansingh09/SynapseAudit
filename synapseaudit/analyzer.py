"""Pure, deterministic checks for a small Docker Compose security slice.

This module only parses configuration data. It never invokes Docker, mounts a
filesystem, contacts a network, or executes a command from a Compose file.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml


class ComposeConfigError(ValueError):
    """Raised when the input is not a usable Compose configuration."""


@dataclass(frozen=True)
class Finding:
    """A deterministic rule result."""

    id: str
    service: str
    severity: str
    title: str
    evidence: str
    remediation: str


@dataclass(frozen=True)
class AttackPath:
    """A bounded explanation joining findings; it is not an exploit."""

    id: str
    service: str
    title: str
    steps: tuple[str, ...]
    impact: str
    remediation: str


@dataclass(frozen=True)
class AnalysisReport:
    """All findings and explanations for one Compose document."""

    findings: tuple[Finding, ...]
    attack_paths: tuple[AttackPath, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [asdict(finding) for finding in self.findings],
            "attack_paths": [asdict(path) for path in self.attack_paths],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


def load_compose(path: Path) -> dict[str, Any]:
    """Load one Compose YAML document without performing any side effects."""

    try:
        with path.open("r", encoding="utf-8") as compose_file:
            document = yaml.safe_load(compose_file)
    except FileNotFoundError as exc:
        raise ComposeConfigError(f"Compose file does not exist: {path}") from exc
    except yaml.YAMLError as exc:
        raise ComposeConfigError(f"Invalid YAML in {path}: {exc}") from exc

    if not isinstance(document, dict):
        raise ComposeConfigError("Compose document must be a YAML mapping")

    services = document.get("services")
    if not isinstance(services, dict) or not services:
        raise ComposeConfigError("Compose document must define a non-empty services mapping")

    return document


def analyze_compose(document: dict[str, Any]) -> AnalysisReport:
    """Run the supported checks in stable service/rule order."""

    services = document.get("services")
    if not isinstance(services, dict) or not services:
        raise ComposeConfigError("Compose document must define a non-empty services mapping")

    findings: list[Finding] = []
    for service_name in sorted(services):
        service = services[service_name]
        if not isinstance(service, dict):
            continue
        findings.extend(_check_privileged(service_name, service))
        findings.extend(_check_writable_bind(service_name, service))

    attack_paths = _correlate_attack_paths(findings)
    return AnalysisReport(tuple(findings), tuple(attack_paths))


def analyze_file(path: Path) -> AnalysisReport:
    """Load and analyze a Compose file."""

    return analyze_compose(load_compose(path))


def _check_privileged(service_name: str, service: dict[str, Any]) -> list[Finding]:
    if service.get("privileged") is not True:
        return []
    return [
        Finding(
            id="PRIVILEGED_CONTAINER",
            service=service_name,
            severity="high",
            title="Service requests privileged container mode",
            evidence=f"services.{service_name}.privileged is true",
            remediation="Remove privileged mode and grant only the narrowly required capabilities.",
        )
    ]


def _check_writable_bind(service_name: str, service: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    volumes = service.get("volumes", [])
    if not isinstance(volumes, list):
        return findings

    for volume in volumes:
        bind_source, target, writable = _parse_volume(volume)
        if bind_source is None or not writable:
            continue
        findings.append(
            Finding(
                id="WRITABLE_HOST_BIND",
                service=service_name,
                severity="medium",
                title="Service can write to a local bind mount",
                evidence=(
                    f"services.{service_name}.volumes maps local source "
                    f"{bind_source!r} to {target!r} with write access"
                ),
                remediation="Use a named volume or make the bind mount read-only with :ro/read_only: true.",
            )
        )
    return findings


def _parse_volume(volume: Any) -> tuple[str | None, str, bool]:
    """Return (local source, target, writable) for supported volume forms."""

    if isinstance(volume, str):
        parts = volume.split(":")
        if len(parts) < 2:
            return None, "", False
        source, target = parts[0], parts[1]
        modes = {mode.strip().lower() for mode in ":".join(parts[2:]).split(",") if mode.strip()}
        return (_is_local_bind_source(source), target, "ro" not in modes)

    if isinstance(volume, dict) and volume.get("type") == "bind":
        source = volume.get("source")
        target = volume.get("target", "")
        if not isinstance(source, str) or not isinstance(target, str):
            return None, "", False
        writable = volume.get("read_only") is not True
        return (_is_local_bind_source(source), target, writable)

    return None, "", False


def _is_local_bind_source(source: str) -> str | None:
    """Recognize explicit local paths, excluding named volumes."""

    if source.startswith(("./", "../", "/", "~/")):
        return source
    return None


def _correlate_attack_paths(findings: list[Finding]) -> list[AttackPath]:
    by_service: dict[str, set[str]] = {}
    for finding in findings:
        by_service.setdefault(finding.service, set()).add(finding.id)

    paths: list[AttackPath] = []
    for service_name in sorted(by_service):
        service_findings = by_service[service_name]
        if {"PRIVILEGED_CONTAINER", "WRITABLE_HOST_BIND"} <= service_findings:
            paths.append(
                AttackPath(
                    id="PRIVILEGE_TO_SHARED-DATA",
                    service=service_name,
                    title="Elevated service can alter data shared with the local workspace",
                    steps=(
                        f"A compromise of service {service_name!r} is the starting condition.",
                        "The service already requests privileged container mode.",
                        "The service can write through a local bind mount, so shared fixture data could be altered.",
                    ),
                    impact="This is a configuration risk explanation only; no command or container action is executed.",
                    remediation="Remove privileged mode and replace the writable bind mount with a read-only or named volume.",
                )
            )
    return paths
