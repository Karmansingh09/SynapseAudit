"""Pure, deterministic checks for a small Docker Compose security slice.

This module only parses configuration data. It never invokes Docker, mounts a
filesystem, contacts a network, or executes a command from a Compose file.
"""

from __future__ import annotations

import ipaddress
import json
import multiprocessing as mp
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml
from yaml.events import (
    AliasEvent,
    DocumentStartEvent,
    MappingEndEvent,
    MappingStartEvent,
    ScalarEvent,
    SequenceEndEvent,
    SequenceStartEvent,
)
from yaml.nodes import MappingNode, Node, SequenceNode


HIGH_RISK_CAPABILITIES = frozenset({"ALL", "NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE"})
PORT_PROTOCOLS = frozenset({"sctp", "tcp", "udp"})


class ComposeConfigError(ValueError):
    """Raised when the input is not a usable Compose configuration."""


class ComposeAnalysisLimitError(ComposeConfigError):
    """Raised when bounded YAML structure or analysis input limits are exceeded."""


class ComposeAnalysisTimeoutError(ComposeConfigError):
    """Raised when an isolated Compose analysis exceeds its deadline."""


class ComposeAnalysisWorkerError(ComposeConfigError):
    """Raised when an isolated Compose analysis worker fails unexpectedly."""


@dataclass(frozen=True)
class ComposeAnalysisLimits:
    """Hard structural ceilings applied before materializing untrusted YAML."""

    max_input_bytes: int = 1 * 1024 * 1024
    max_yaml_depth: int = 64
    max_yaml_events: int = 20_000
    max_yaml_aliases: int = 128
    max_yaml_scalar_chars: int = 1 * 1024 * 1024
    max_yaml_collection_items: int = 2_000
    max_services: int = 200
    max_service_items: int = 1_000
    max_duration_seconds: float = 5.0


DEFAULT_COMPOSE_ANALYSIS_LIMITS = ComposeAnalysisLimits()


@dataclass(frozen=True)
class Finding:
    """A deterministic rule result."""

    id: str
    service: str
    severity: str
    title: str
    explanation: str
    impact: str
    evidence: str
    remediation: str
    limitations: str
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None


@dataclass(frozen=True)
class AttackPath:
    """A bounded explanation joining findings; it is not an exploit."""

    id: str
    service: str
    title: str
    classification: str
    steps: tuple[str, ...]
    impact: str
    remediation: str
    limitations: str


@dataclass(frozen=True)
class _PortMapping:
    published: str
    target: str
    protocol: str
    host_ip: str | None


@dataclass(frozen=True)
class _SourceLocation:
    """One-based source lines for an analyzer-relevant YAML node."""

    start: int
    end: int


@dataclass(frozen=True)
class _ServiceSource:
    fields: dict[str, _SourceLocation]
    items: dict[str, tuple[_SourceLocation, ...]]


@dataclass(frozen=True)
class _ComposeSource:
    services: dict[str, _ServiceSource]


@dataclass(frozen=True)
class AnalysisReport:
    """All findings and explanations for one Compose document."""

    findings: tuple[Finding, ...]
    attack_paths: tuple[AttackPath, ...]

    def to_dict(self) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        for finding in self.findings:
            finding_dict = asdict(finding)
            if finding.file_path is None:
                finding_dict.pop("file_path", None)
                finding_dict.pop("line_start", None)
                finding_dict.pop("line_end", None)
            findings.append(finding_dict)
        return {
            "findings": findings,
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


def analyze_compose(
    document: Any,
    *,
    source_file: str | None = None,
    source: _ComposeSource | None = None,
) -> AnalysisReport:
    """Run the supported checks in stable service/rule order.

    ``source_file`` and ``source`` are optional so existing local callers keep
    the original report shape. Repository scans provide both to attach trusted
    repository-relative paths and YAML source lines to findings.
    """

    services = _get_services(document)

    findings: list[Finding] = []
    for service_name in sorted(services):
        service = services[service_name]
        if not isinstance(service, dict):
            continue
        findings.extend(
            _check_privileged(
                service_name,
                service,
                source_file=source_file,
                location=_field_location(source, service_name, "privileged"),
            )
        )
        findings.extend(
            _check_dangerous_capabilities(
                service_name,
                service,
                source_file=source_file,
                source=source,
            )
        )
        findings.extend(
            _check_exposed_ports(
                service_name,
                service,
                source_file=source_file,
                source=source,
            )
        )
        findings.extend(
            _check_writable_bind(
                service_name,
                service,
                source_file=source_file,
                source=source,
            )
        )

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


def analyze_compose_bytes(
    content: bytes,
    *,
    source_file: str | None = None,
) -> AnalysisReport:
    """Decode and analyze bounded UTF-8 Compose content without filesystem access."""

    return _analyze_compose_bytes_in_process(
        content,
        source_file=source_file,
        limits=DEFAULT_COMPOSE_ANALYSIS_LIMITS,
    )


def analyze_compose_bytes_bounded(
    content: bytes,
    *,
    source_file: str | None = None,
    limits: ComposeAnalysisLimits = DEFAULT_COMPOSE_ANALYSIS_LIMITS,
    timeout_seconds: float | None = None,
    worker: Any = None,
) -> AnalysisReport:
    """Analyze Compose bytes in a killable process with a hard wall-clock bound.

    The worker receives only immutable bytes and structural limits. A fresh
    ``spawn`` process is used for each document so a timed-out YAML parser
    cannot continue consuming request-thread resources.
    """

    if not isinstance(content, (bytes, bytearray)):
        raise TypeError("Compose content must be bytes")
    content_bytes = bytes(content)
    if not content_bytes:
        raise ComposeConfigError("Compose content must not be empty")
    if len(content_bytes) > limits.max_input_bytes:
        raise ComposeAnalysisLimitError("Compose content exceeds the bounded input limit")
    if timeout_seconds is None:
        timeout_seconds = limits.max_duration_seconds
    if timeout_seconds <= 0:
        raise ComposeAnalysisTimeoutError("Compose analysis deadline was exhausted")

    context = mp.get_context("spawn")
    parent_connection, child_connection = context.Pipe(duplex=False)
    analysis_worker = worker or _compose_analysis_worker
    process = context.Process(
        target=analysis_worker,
        args=(child_connection, content_bytes, source_file, limits),
    )
    deadline = time.monotonic() + timeout_seconds
    try:
        try:
            process.start()
        except (OSError, RuntimeError) as exc:
            raise ComposeAnalysisWorkerError("Compose analysis worker could not start") from exc
        child_connection.close()

        remaining = deadline - time.monotonic()
        if remaining <= 0 or not parent_connection.poll(remaining):
            raise ComposeAnalysisTimeoutError("Compose analysis exceeded its deadline")
        try:
            message = parent_connection.recv()
        except (EOFError, OSError) as exc:
            raise ComposeAnalysisWorkerError("Compose analysis worker returned no result") from exc
        if time.monotonic() > deadline:
            raise ComposeAnalysisTimeoutError("Compose analysis exceeded its deadline")
        if not isinstance(message, tuple) or len(message) != 2:
            raise ComposeAnalysisWorkerError("Compose analysis worker returned an invalid result")
        result_type, result_value = message
        if result_type == "ok" and isinstance(result_value, AnalysisReport):
            return result_value
        if result_type == "compose_error" and isinstance(result_value, str):
            raise ComposeConfigError(result_value)
        if result_type == "limit_error" and isinstance(result_value, str):
            raise ComposeAnalysisLimitError(result_value)
        raise ComposeAnalysisWorkerError("Compose analysis worker returned an invalid result")
    finally:
        _cleanup_analysis_process(process)
        try:
            child_connection.close()
        except OSError:
            pass
        try:
            parent_connection.close()
        except OSError:
            pass


def _cleanup_analysis_process(process: Any) -> None:
    """Stop a worker reliably without relying on daemon-thread cleanup."""

    if not getattr(process, "_popen", None):
        return
    try:
        process.join(0.05)
        if process.is_alive():
            process.terminate()
            process.join(0.2)
        if process.is_alive() and hasattr(process, "kill"):
            process.kill()
            process.join(0.2)
    finally:
        if not process.is_alive():
            try:
                process.close()
            except (OSError, ValueError):
                pass


def _compose_analysis_worker(
    connection: Any,
    content: bytes,
    source_file: str | None,
    limits: ComposeAnalysisLimits,
) -> None:
    try:
        report = _analyze_compose_bytes_in_process(
            content,
            source_file=source_file,
            limits=limits,
        )
        connection.send(("ok", report))
    except ComposeAnalysisLimitError as exc:
        connection.send(("limit_error", str(exc)))
    except ComposeConfigError as exc:
        connection.send(("compose_error", str(exc)))
    except BaseException:
        try:
            connection.send(("worker_error", "Compose analysis worker failed"))
        except (BrokenPipeError, EOFError, OSError):
            pass
    finally:
        connection.close()


def _analyze_compose_bytes_in_process(
    content: bytes,
    *,
    source_file: str | None,
    limits: ComposeAnalysisLimits,
) -> AnalysisReport:
    """Perform parsing and deterministic analysis inside the bounded worker."""

    if not isinstance(content, (bytes, bytearray)):
        raise TypeError("Compose content must be bytes")
    if not content:
        raise ComposeConfigError("Compose content must not be empty")
    if len(content) > limits.max_input_bytes:
        raise ComposeAnalysisLimitError("Compose content exceeds the bounded input limit")

    try:
        text = bytes(content).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ComposeConfigError("Compose content must be valid UTF-8") from exc

    _preflight_yaml(text, limits)
    try:
        document = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError) as exc:
        raise ComposeConfigError("Compose content is not valid YAML") from exc

    _validate_document_limits(document, limits)
    source = _build_source_map(text) if source_file else None
    return analyze_compose(document, source_file=source_file, source=source)


def _preflight_yaml(text: str, limits: ComposeAnalysisLimits) -> None:
    """Bound parser events, nesting, aliases, scalars, and collection fan-out."""

    event_count = 0
    document_count = 0
    alias_count = 0
    scalar_chars = 0
    depth = 0
    collection_counts: list[int] = []
    try:
        events = yaml.parse(text)
        for event in events:
            event_count += 1
            if event_count > limits.max_yaml_events:
                raise ComposeAnalysisLimitError("Compose YAML event limit exceeded")
            if isinstance(event, DocumentStartEvent):
                document_count += 1
                if document_count > 1:
                    raise ComposeAnalysisLimitError("Multiple YAML documents are not supported")
            if isinstance(event, AliasEvent):
                alias_count += 1
                if alias_count > limits.max_yaml_aliases:
                    raise ComposeAnalysisLimitError("Compose YAML alias limit exceeded")
                _increment_collection_count(collection_counts, limits)
            elif isinstance(event, ScalarEvent):
                scalar_chars += len(event.value)
                if scalar_chars > limits.max_yaml_scalar_chars:
                    raise ComposeAnalysisLimitError("Compose YAML scalar limit exceeded")
                _increment_collection_count(collection_counts, limits)
            elif isinstance(event, (MappingStartEvent, SequenceStartEvent)):
                _increment_collection_count(collection_counts, limits)
                depth += 1
                if depth > limits.max_yaml_depth:
                    raise ComposeAnalysisLimitError("Compose YAML nesting limit exceeded")
                collection_counts.append(0)
            elif isinstance(event, (MappingEndEvent, SequenceEndEvent)):
                if collection_counts:
                    collection_counts.pop()
                depth = max(0, depth - 1)
    except ComposeAnalysisLimitError:
        raise
    except (yaml.YAMLError, RecursionError) as exc:
        raise ComposeConfigError("Compose content is not valid YAML") from exc
    if document_count != 1:
        raise ComposeConfigError("Compose content must contain exactly one YAML document")


def _increment_collection_count(
    collection_counts: list[int],
    limits: ComposeAnalysisLimits,
) -> None:
    if not collection_counts:
        return
    collection_counts[-1] += 1
    if collection_counts[-1] > limits.max_yaml_collection_items:
        raise ComposeAnalysisLimitError("Compose YAML collection limit exceeded")


def _validate_document_limits(document: Any, limits: ComposeAnalysisLimits) -> None:
    if not isinstance(document, dict):
        return
    services = document.get("services")
    if isinstance(services, dict) and len(services) > limits.max_services:
        raise ComposeAnalysisLimitError("Compose service limit exceeded")
    if not isinstance(services, dict):
        return
    for service in services.values():
        if not isinstance(service, dict):
            continue
        for field_name in ("cap_add", "ports", "volumes"):
            values = service.get(field_name)
            if isinstance(values, list) and len(values) > limits.max_service_items:
                raise ComposeAnalysisLimitError(
                    f"Compose {field_name} item limit exceeded"
                )


def _build_source_map(text: str) -> _ComposeSource | None:
    """Build locations from PyYAML nodes without searching source text."""

    try:
        root = yaml.compose(text)
    except (yaml.YAMLError, RecursionError):
        return None
    if not isinstance(root, MappingNode):
        return None

    services_node: Node | None = None
    for key_node, value_node in root.value:
        if isinstance(key_node, yaml.ScalarNode) and key_node.value == "services":
            services_node = value_node
            break
    if not isinstance(services_node, MappingNode):
        return None

    services: dict[str, _ServiceSource] = {}
    for service_key, service_node in services_node.value:
        if not isinstance(service_key, yaml.ScalarNode) or not isinstance(service_node, MappingNode):
            continue
        fields: dict[str, _SourceLocation] = {}
        items: dict[str, tuple[_SourceLocation, ...]] = {}
        for field_key, field_node in service_node.value:
            if not isinstance(field_key, yaml.ScalarNode):
                continue
            field_name = str(field_key.value)
            fields[field_name] = _node_location(field_node)
            if isinstance(field_node, SequenceNode):
                items[field_name] = tuple(_node_location(item) for item in field_node.value)
        services[str(service_key.value)] = _ServiceSource(fields=fields, items=items)
    return _ComposeSource(services=services)


def _node_location(node: Node) -> _SourceLocation:
    start = node.start_mark.line + 1
    end = node.end_mark.line + 1
    if node.end_mark.column == 0 and end > start:
        end -= 1
    return _SourceLocation(start=start, end=max(start, end))


def _field_location(
    source: _ComposeSource | None,
    service_name: str,
    field_name: str,
) -> _SourceLocation | None:
    if source is None:
        return None
    service_source = source.services.get(service_name)
    return service_source.fields.get(field_name) if service_source else None


def _item_location(
    source: _ComposeSource | None,
    service_name: str,
    field_name: str,
    index: int,
) -> _SourceLocation | None:
    if source is None:
        return None
    service_source = source.services.get(service_name)
    if service_source is None:
        return None
    locations = service_source.items.get(field_name, ())
    return locations[index] if index < len(locations) else service_source.fields.get(field_name)


def _merge_locations(locations: list[_SourceLocation]) -> _SourceLocation | None:
    if not locations:
        return None
    return _SourceLocation(
        start=min(location.start for location in locations),
        end=max(location.end for location in locations),
    )


def _finding_metadata(
    source_file: str | None,
    location: _SourceLocation | None,
) -> dict[str, Any]:
    if source_file is None:
        return {}
    return {
        "file_path": source_file,
        "line_start": location.start if location else None,
        "line_end": location.end if location else None,
    }


def _check_privileged(
    service_name: str,
    service: dict[str, Any],
    *,
    source_file: str | None = None,
    location: _SourceLocation | None = None,
) -> list[Finding]:
    if service.get("privileged") is not True:
        return []
    return [
        Finding(
            id="PRIVILEGED_CONTAINER",
            service=service_name,
            severity="high",
            title="Service requests privileged container mode",
            explanation=(
                "The service explicitly requests privileged container mode, which "
                "broadens its privileges beyond normal container isolation."
            ),
            impact=(
                "If the service is compromised, privileged mode may increase access "
                "to host kernel and device resources."
            ),
            evidence=f"services.{service_name}.privileged is true",
            remediation="Remove privileged mode and grant only the narrowly required capabilities.",
            limitations=(
                "This is a static check of the explicit flag; it does not inspect "
                "runtime privileges, host configuration, or whether the request is required."
            ),
            **_finding_metadata(source_file, location),
        )
    ]


def _check_dangerous_capabilities(
    service_name: str,
    service: dict[str, Any],
    *,
    source_file: str | None = None,
    source: _ComposeSource | None = None,
) -> list[Finding]:
    if "cap_add" not in service:
        return []

    cap_add = service["cap_add"]
    if not isinstance(cap_add, list):
        raise ComposeConfigError(f"services.{service_name}.cap_add must be a list")

    dangerous: list[str] = []
    dangerous_locations: list[_SourceLocation] = []
    for index, capability in enumerate(cap_add):
        if not isinstance(capability, str) or not capability.strip():
            raise ComposeConfigError(
                f"services.{service_name}.cap_add entries must be non-empty strings"
            )
        normalized = _normalize_capability(capability)
        if normalized in HIGH_RISK_CAPABILITIES and normalized not in dangerous:
            dangerous.append(normalized)
            location = _item_location(source, service_name, "cap_add", index)
            if location is not None:
                dangerous_locations.append(location)

    if not dangerous:
        return []

    return [
        Finding(
            id="DANGEROUS_CAPABILITY",
            service=service_name,
            severity="high",
            title="Service adds a high-risk Linux capability",
            explanation=(
                "The service adds one or more Linux capabilities that can materially "
                "expand what its processes can do."
            ),
            impact=(
                "A compromised process may use these capabilities to weaken container "
                "isolation or affect protected host and kernel operations."
            ),
            evidence=(
                f"services.{service_name}.cap_add includes "
                f"{', '.join(dangerous)}"
            ),
            remediation=(
                "Remove high-risk capabilities unless strictly required; if one is "
                "necessary, grant the smallest documented capability set."
            ),
            limitations=(
                "Only explicit cap_add values in the supported high-risk set are "
                "checked; runtime capability state and kernel policy are not inspected."
            ),
            **_finding_metadata(
                source_file,
                _merge_locations(dangerous_locations)
                or _field_location(source, service_name, "cap_add"),
            ),
        )
    ]


def _normalize_capability(capability: str) -> str:
    normalized = capability.strip().upper()
    if normalized.startswith("CAP_"):
        normalized = normalized[4:]
    return normalized


def _check_exposed_ports(
    service_name: str,
    service: dict[str, Any],
    *,
    source_file: str | None = None,
    source: _ComposeSource | None = None,
) -> list[Finding]:
    if "ports" not in service:
        return []

    ports = service["ports"]
    if not isinstance(ports, list):
        raise ComposeConfigError(f"services.{service_name}.ports must be a list")

    findings: list[Finding] = []
    for index, port in enumerate(ports):
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
                explanation=(
                    "The Compose ports entry publishes a container port on "
                    f"{published} ({scope}), making the service reachable through a host binding."
                ),
                impact=(
                    "A host-published port expands the service's potential reachability "
                    "and may expose an attack surface beyond the Compose network."
                ),
                evidence=(
                    f"services.{service_name}.ports publishes container port "
                    f"{mapping.target} on {published} ({scope}, {mapping.protocol})"
                ),
                remediation=(
                    "Remove host publication when it is not required; otherwise bind "
                    "intentionally and enforce exposure controls outside this static analysis."
                ),
                limitations=(
                    "Only explicit ports mappings are analyzed; this does not probe the "
                    "service, inspect firewall policy, or determine actual network reachability."
                ),
                **_finding_metadata(
                    source_file,
                    _item_location(source, service_name, "ports", index),
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


def _check_writable_bind(
    service_name: str,
    service: dict[str, Any],
    *,
    source_file: str | None = None,
    source: _ComposeSource | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    if "volumes" not in service:
        return findings
    volumes = service["volumes"]
    if not isinstance(volumes, list):
        raise ComposeConfigError(f"services.{service_name}.volumes must be a list")

    for index, volume in enumerate(volumes):
        bind_source, target, writable = _parse_volume(volume)
        if bind_source is None or not writable:
            continue
        findings.append(
            Finding(
                id="WRITABLE_HOST_BIND",
                service=service_name,
                severity="medium",
                title="Service can write to a local bind mount",
                explanation=(
                    "The service maps a local host path into the container with write "
                    "access, allowing container processes to modify shared data."
                ),
                impact=(
                    "If the service is compromised, it may alter files in the mapped "
                    "workspace or host path and affect other local workflows."
                ),
                evidence=(
                    f"services.{service_name}.volumes maps local source "
                    f"{bind_source!r} to {target!r} with write access"
                ),
                remediation="Use a named volume or make the bind mount read-only with :ro/read_only: true.",
                limitations=(
                    "Only explicit local bind syntax is checked; this does not inspect "
                    "host permissions, runtime mounts, or unsupported volume backends."
                ),
                **_finding_metadata(
                    source_file,
                    _item_location(source, service_name, "volumes", index),
                ),
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
                    title="Hypothetical privilege-to-shared-data risk scenario",
                    classification="deterministic_hypothetical_correlation",
                    steps=(
                        f"A compromise of service {service_name!r} is the starting condition.",
                        "The service already requests privileged container mode.",
                        "The service can write through a local bind mount, so shared fixture data could be altered.",
                    ),
                    impact="This is a configuration risk explanation only; no command or container action is executed.",
                    remediation="Remove privileged mode and replace the writable bind mount with a read-only or named volume.",
                    limitations=(
                        "This correlation joins two findings on one service; it is not "
                        "proof of exploitation and is not a generalized attack graph."
                    ),
                )
            )
    return paths
