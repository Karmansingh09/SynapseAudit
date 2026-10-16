"""Pure, deterministic checks for a small Docker Compose security slice.

This module only parses configuration data. It never invokes Docker, mounts a
filesystem, contacts a network, or executes a command from a Compose file.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml


HIGH_RISK_CAPABILITIES = frozenset({"ALL", "NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE"})
PORT_PROTOCOLS = frozenset({"sctp", "tcp", "udp"})


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
class _PortMapping:
    published: str
    target: str
    protocol: str
    host_ip: str | None


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
    except (OSError, UnicodeError) as exc:
        raise ComposeConfigError(f"Could not read Compose file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ComposeConfigError(f"Invalid YAML in {path}: {exc}") from exc

    _get_services(document)

    return document


def analyze_compose(document: Any) -> AnalysisReport:
    """Run the supported checks in stable service/rule order."""

    services = _get_services(document)

    findings: list[Finding] = []
    for service_name in sorted(services):
        service = services[service_name]
        if not isinstance(service, dict):
            continue
        findings.extend(_check_privileged(service_name, service))
        findings.extend(_check_dangerous_capabilities(service_name, service))
        findings.extend(_check_exposed_ports(service_name, service))
        findings.extend(_check_writable_bind(service_name, service))

    attack_paths = _correlate_attack_paths(findings)
    return AnalysisReport(tuple(findings), tuple(attack_paths))


def _get_services(document: Any) -> dict[str, Any]:
    """Validate the Compose shape needed by the analyzer before scanning it."""

    if not isinstance(document, dict):
        raise ComposeConfigError("Compose document must be a YAML mapping")

    services = document.get("services")
    if not isinstance(services, dict) or not services:
        raise ComposeConfigError("Compose document must define a non-empty services mapping")

    for service_name, service in services.items():
        if not isinstance(service_name, str) or not service_name:
            raise ComposeConfigError("Compose service names must be non-empty strings")
        if not isinstance(service, dict):
            raise ComposeConfigError(f"Compose service {service_name!r} must be a mapping")
        if "privileged" in service and not isinstance(service["privileged"], bool):
            raise ComposeConfigError(f"services.{service_name}.privileged must be boolean")
        restart = service.get("restart")
        if restart is not None and not isinstance(restart, (str, dict)):
            raise ComposeConfigError(
                f"services.{service_name}.restart must be a string or mapping"
            )

    return services


def analyze_file(path: Path) -> AnalysisReport:
    """Load and analyze a Compose file."""

    return analyze_compose(load_compose(path))


def analyze_compose_bytes(content: bytes) -> AnalysisReport:
    """Decode and analyze bounded UTF-8 Compose content without filesystem access."""

    if not isinstance(content, (bytes, bytearray)):
        raise TypeError("Compose content must be bytes")
    if not content:
        raise ComposeConfigError("Compose content must not be empty")

    try:
        text = bytes(content).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ComposeConfigError("Compose content must be valid UTF-8") from exc

    try:
        document = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError) as exc:
        raise ComposeConfigError("Compose content is not valid YAML") from exc

    return analyze_compose(document)


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


def _check_dangerous_capabilities(service_name: str, service: dict[str, Any]) -> list[Finding]:
    if "cap_add" not in service:
        return []

    cap_add = service["cap_add"]
    if not isinstance(cap_add, list):
        raise ComposeConfigError(f"services.{service_name}.cap_add must be a list")

    dangerous: list[str] = []
    for capability in cap_add:
        if not isinstance(capability, str) or not capability.strip():
            raise ComposeConfigError(
                f"services.{service_name}.cap_add entries must be non-empty strings"
            )
        normalized = _normalize_capability(capability)
        if normalized in HIGH_RISK_CAPABILITIES and normalized not in dangerous:
            dangerous.append(normalized)

    if not dangerous:
        return []

    return [
        Finding(
            id="DANGEROUS_CAPABILITY",
            service=service_name,
            severity="high",
            title="Service adds a high-risk Linux capability",
            evidence=(
                f"services.{service_name}.cap_add includes "
                f"{', '.join(dangerous)}"
            ),
            remediation=(
                "Remove high-risk capabilities unless strictly required; if one is "
                "necessary, grant the smallest documented capability set."
            ),
        )
    ]


def _normalize_capability(capability: str) -> str:
    normalized = capability.strip().upper()
    if normalized.startswith("CAP_"):
        normalized = normalized[4:]
    return normalized


def _check_exposed_ports(service_name: str, service: dict[str, Any]) -> list[Finding]:
    if "ports" not in service:
        return []

    ports = service["ports"]
    if not isinstance(ports, list):
        raise ComposeConfigError(f"services.{service_name}.ports must be a list")

    findings: list[Finding] = []
    for port in ports:
        mapping = _parse_port_mapping(port, service_name)
        if mapping is None:
            continue

        scope = _port_binding_scope(mapping.host_ip)
        published = (
            "a dynamically assigned host port"
            if mapping.published == "dynamic"
            else f"host port {mapping.published}"
        )
        findings.append(
            Finding(
                id="EXPOSED_SERVICE_PORT",
                service=service_name,
                severity="medium",
                title="Service publishes a host port",
                evidence=(
                    f"services.{service_name}.ports publishes container port "
                    f"{mapping.target} on {published} ({scope}, {mapping.protocol})"
                ),
                remediation=(
                    "Remove host publication when it is not required; otherwise bind "
                    "intentionally and enforce exposure controls outside this static analysis."
                ),
            )
        )
    return findings


def _parse_port_mapping(port: Any, service_name: str) -> _PortMapping | None:
    if isinstance(port, str):
        return _parse_short_port_mapping(port, service_name)
    if isinstance(port, dict):
        return _parse_long_port_mapping(port, service_name)
    raise ComposeConfigError(
        f"services.{service_name}.ports entries must be strings or mappings"
    )


def _parse_short_port_mapping(port: str, service_name: str) -> _PortMapping | None:
    if not port.strip():
        raise ComposeConfigError(f"services.{service_name}.ports entries must be non-empty")

    port_spec, protocol = _split_port_protocol(port, service_name)
    if port_spec.startswith("["):
        closing_bracket = port_spec.find("]")
        if closing_bracket < 0 or closing_bracket + 1 >= len(port_spec) or port_spec[closing_bracket + 1] != ":":
            raise ComposeConfigError(f"Invalid port mapping for services.{service_name}: {port}")
        host_ip = port_spec[1:closing_bracket]
        parts = port_spec[closing_bracket + 2 :].split(":")
        if len(parts) != 2:
            raise ComposeConfigError(f"Invalid port mapping for services.{service_name}: {port}")
    else:
        parts = port_spec.split(":")
        if len(parts) == 1:
            _normalize_port_token(parts[0], "target", service_name)
            return None
        if len(parts) == 2:
            host_ip = None
        elif len(parts) == 3:
            host_ip, parts = parts[0], parts[1:]
        else:
            raise ComposeConfigError(f"Invalid port mapping for services.{service_name}: {port}")

    published = _normalize_port_token(parts[0], "published", service_name, allow_dynamic=True)
    target = _normalize_port_token(parts[1], "target", service_name)
    normalized_host_ip = _normalize_host_ip(host_ip, service_name)
    return _PortMapping(published, target, protocol, normalized_host_ip)


def _parse_long_port_mapping(port: dict[str, Any], service_name: str) -> _PortMapping | None:
    if "target" not in port:
        raise ComposeConfigError(f"services.{service_name}.ports target is required")

    target = _normalize_port_token(port["target"], "target", service_name)
    if "published" not in port:
        return None

    published = _normalize_port_token(
        port["published"], "published", service_name, allow_dynamic=True
    )
    protocol = _normalize_port_protocol(port.get("protocol", "tcp"), service_name)
    normalized_host_ip = _normalize_host_ip(port.get("host_ip"), service_name)
    return _PortMapping(published, target, protocol, normalized_host_ip)


def _split_port_protocol(port: str, service_name: str) -> tuple[str, str]:
    if "/" not in port:
        return port, "tcp"
    port_spec, protocol = port.rsplit("/", 1)
    return port_spec, _normalize_port_protocol(protocol, service_name)


def _normalize_port_protocol(protocol: Any, service_name: str) -> str:
    if not isinstance(protocol, str) or protocol.strip().lower() not in PORT_PROTOCOLS:
        raise ComposeConfigError(
            f"services.{service_name}.ports protocol must be tcp, udp, or sctp"
        )
    return protocol.strip().lower()


def _normalize_port_token(
    value: Any,
    field: str,
    service_name: str,
    *,
    allow_dynamic: bool = False,
) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ComposeConfigError(f"services.{service_name}.ports {field} must be a port value")
    token = str(value).strip()
    if not token and allow_dynamic:
        return "dynamic"
    if not token:
        raise ComposeConfigError(f"services.{service_name}.ports {field} must not be empty")

    bounds = token.split("-")
    if len(bounds) > 2 or any(not bound.isdigit() for bound in bounds):
        raise ComposeConfigError(f"services.{service_name}.ports {field} is not a valid port")
    numbers = [int(bound) for bound in bounds]
    if any(number < 1 or number > 65535 for number in numbers):
        raise ComposeConfigError(f"services.{service_name}.ports {field} is outside 1-65535")
    if len(numbers) == 2 and numbers[0] > numbers[1]:
        raise ComposeConfigError(f"services.{service_name}.ports {field} has a descending range")
    return token


def _normalize_host_ip(host_ip: Any, service_name: str) -> str | None:
    if host_ip is None or host_ip == "":
        return None
    if not isinstance(host_ip, str):
        raise ComposeConfigError(f"services.{service_name}.ports host_ip must be an IP address")
    try:
        ipaddress.ip_address(host_ip)
    except ValueError as exc:
        raise ComposeConfigError(
            f"services.{service_name}.ports host_ip must be an IP address"
        ) from exc
    return host_ip


def _port_binding_scope(host_ip: str | None) -> str:
    if host_ip is None:
        return "all host interfaces"
    address = ipaddress.ip_address(host_ip)
    if address.is_loopback:
        return "loopback only"
    if address.is_unspecified:
        return "all host interfaces"
    return f"host interface {host_ip}"


def _check_writable_bind(service_name: str, service: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if "volumes" not in service:
        return findings
    volumes = service["volumes"]
    if not isinstance(volumes, list):
        raise ComposeConfigError(f"services.{service_name}.volumes must be a list")

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
        if not volume.strip():
            raise ComposeConfigError("A short-syntax volume must be a non-empty string")
        parts = volume.split(":")
        if len(parts) < 2:
            if volume.startswith("/"):
                return None, volume, False
            raise ComposeConfigError("A short-syntax volume must define a target path")
        source, target = parts[0], parts[1]
        if not source or not target:
            raise ComposeConfigError("A short-syntax volume must define source and target paths")
        modes = {mode.strip().lower() for mode in ":".join(parts[2:]).split(",") if mode.strip()}
        return (_is_local_bind_source(source), target, "ro" not in modes)

    if isinstance(volume, dict):
        volume_type = volume.get("type")
        if not isinstance(volume_type, str) or not volume_type:
            raise ComposeConfigError("A long-syntax volume must define a non-empty type")
        target = volume.get("target")
        if not isinstance(target, str) or not target:
            raise ComposeConfigError("A long-syntax volume must define a non-empty target")
        if volume_type != "bind":
            return None, target, False

        source = volume.get("source")
        if not isinstance(source, str) or not source:
            raise ComposeConfigError("A bind volume must define a non-empty string source")
        read_only = volume.get("read_only", False)
        if not isinstance(read_only, bool):
            raise ComposeConfigError("A bind volume read_only field must be boolean")
        writable = not read_only
        return (_is_local_bind_source(source), target, writable)

    if not isinstance(volume, (str, dict)):
        raise ComposeConfigError("Each Compose volume must be a string or mapping")

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
