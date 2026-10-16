# SynapseAudit

SynapseAudit is a small, safe, repeatable Docker Compose configuration
analyzer for the OmniRush Frontier Buildathon Systems, Infrastructure &
Cybersecurity track.

It currently checks four configuration risks:

1. `privileged: true` on a service.
2. A writable local bind mount such as `./fixture-data:/app/data:rw`.
3. Explicit high-risk capability additions through `cap_add`: `ALL`,
   `NET_ADMIN`, `SYS_ADMIN`, or `SYS_PTRACE`.
4. Explicit host-published service ports through `ports`.

When the privileged-container and writable-bind checks apply to one service, it
emits a bounded attack-path explanation. The explanation is static analysis, not
an exploit: SynapseAudit does not start Compose services, execute configuration
content, contact external systems, read host resources, or access/mount the
Docker socket.

## Architecture

- `synapseaudit/analyzer.py` loads YAML with `yaml.safe_load`, runs deterministic
  rules, validates the required Compose structure, and correlates findings in
  stable order.
- `synapseaudit/cli.py` exposes text and JSON output.
- `synapseaudit/web.py` serves a loopback-only public landing page at `/`, the
  functional dashboard at `/console`, and an allowlisted fixture-analysis API
  using the existing analyzer directly.
- `synapseaudit/static/landing.html` is a dependency-free technical overview of
  the analyzer's deterministic checks, one correlation, and safety boundaries.
- `synapseaudit/static/dashboard.html` and
  `synapseaudit/static/dashboard.js` are the dependency-free dashboard UI and
  behavior. The local server sends a restrictive Content Security Policy and
  defensive response headers for these assets, the API, and error responses.
- `fixtures/compose.vulnerable.yml` is a deliberately vulnerable but harmless
  local fixture. Its bind source is only `fixtures/fixture-data`.
- `fixtures/compose.remediated.yml` removes privileged mode and high-risk
  capabilities, removes host port publication, and makes the bind mount
  read-only.
- `tests/` verifies all four checks, the correlation, CLI serialization, and the
  remediation result.

The current implementation does not include AI-assisted planning or automated
patch generation. Rule evaluation and remediation verification are deterministic
code paths.

## 60-second demo

From the repository root, create the pinned virtual environment and install the
locked dependency:

```sh
make setup
```

Run the deliberately vulnerable fixture:

```sh
.venv/bin/python -m synapseaudit.cli fixtures/compose.vulnerable.yml
```

Run the remediated fixture:

```sh
.venv/bin/python -m synapseaudit.cli fixtures/compose.remediated.yml
```

Use JSON output when showing the result to another tool:

```sh
.venv/bin/python -m synapseaudit.cli --format json fixtures/compose.vulnerable.yml
```

Expected results:

- Vulnerable fixture: **4 findings** and **1 attack path**.
- Remediated fixture: **0 findings** and **0 attack paths**.
- JSON output contains the same deterministic findings and attack path in a
  machine-readable structure.

The commands analyze YAML only. They do not start Compose services.

`EXPOSED_SERVICE_PORT` means that Compose requests host publication. The output
identifies all-interface, loopback-only, or specific-interface bindings, but it
does not prove internet reachability, firewall exposure, routing, proxy access,
or that the service is running. The current parser supports numeric and numeric
range values in short and long port syntax; it does not expand environment
interpolation inside port values.

## Before/after demonstration

| Check | Vulnerable fixture value | Remediated fixture value | Expected result |
| --- | --- | --- | --- |
| Privileged container mode | `privileged: true` | `privileged: false` | One high-severity finding becomes absent |
| High-risk capability | `cap_add: [SYS_ADMIN]` | no `cap_add` entry | One high-severity finding becomes absent |
| Host-published service port | `ports: ["8080:80"]` | no `ports` entry | One medium-severity finding becomes absent |
| Writable local bind mount | `./fixture-data:/app/data:rw` | `./fixture-data:/app/data:ro` | One medium-severity finding becomes absent |
| Combined result | 4 findings, 1 attack path | 0 findings, 0 attack paths | The correlated path disappears after remediation |

## Setup

The runtime is pinned to Python 3.11.4 in `.python-version`. The only runtime
dependency, `PyYAML==6.0.2`, is pinned in `requirements.lock`. These pins
document and stabilize the Python inputs; they do not make every environment or
Docker image bit-for-bit reproducible. The initial setup may need package
access once.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --requirement requirements.lock
```

After installation, the test and analysis commands below are offline and do not
start Docker.

## Run

Analyze the deliberately vulnerable fixture:

```sh
.venv/bin/python -m synapseaudit.cli fixtures/compose.vulnerable.yml
```

Use JSON for automation:

```sh
.venv/bin/python -m synapseaudit.cli --format json fixtures/compose.vulnerable.yml
```

Analyze the remediated configuration and confirm it reports zero findings:

```sh
.venv/bin/python -m synapseaudit.cli fixtures/compose.remediated.yml
```

Do not run either fixture with `docker compose up`; the project demonstrates
configuration analysis only and does not need a container runtime.

## Local dashboard

Start the dependency-free dashboard from the repository root:

```sh
make dashboard
```

Open the printed local URL, normally, to view the public landing page:

```text
http://127.0.0.1:8765
```

The landing page describes the analyzer's four checks, one bounded attack-path
correlation, and safety boundaries. Select **Open the console** or visit the
functional dashboard directly at:

```text
http://127.0.0.1:8765/console
```

The console lets you select the vulnerable or remediated fixture, then displays
live analyzer findings, severity counts, evidence, remediation, the bounded
attack-path explanation, and a before/after comparison computed from both
fixture reports. Use `Ctrl-C` to stop the local server.

The API is intentionally narrow:

```sh
curl http://127.0.0.1:8765/api/analyze?fixture=vulnerable
curl http://127.0.0.1:8765/api/analyze?fixture=remediated
```

Only the two repository-owned fixture IDs are accepted. The server binds to
`127.0.0.1`, rejects arbitrary paths and uploads, calls the analyzer directly,
and never runs Compose, shell commands, images, or Docker API operations. The
dashboard uses DOM text rendering for analyzer-provided strings and does not
make security decisions with AI.

To choose another local port without changing the network host:

```sh
.venv/bin/python -m synapseaudit.web --port 8766
```

## Test

The single project test command is:

```sh
make test
```

It uses Python's standard-library `unittest` runner and the already-installed,
pinned dependency. It does not access the network or Docker.

Malformed YAML and malformed required Compose structures are rejected with an
error rather than being reported as a clean configuration. Unsupported but
valid volume types remain outside the scope of the existing bind-mount check.

## Containerized analyzer run

The Dockerfile packages the analyzer and local fixtures. It does not include a
Docker socket or any host-directory mount:

```sh
docker build -t synapseaudit:local .
docker run --rm synapseaudit:local fixtures/compose.vulnerable.yml
```

This runs the analyzer inside the image as the dedicated unprivileged
`synapseaudit` user; it does not run the analyzed Compose file. The Dockerfile
uses the version-tagged `python:3.11.4-slim` base image, not an immutable digest.
Therefore, Python and PyYAML versions are pinned, but the Docker image is not
guaranteed to be bit-for-bit reproducible unless the base image is later pinned
by digest. A clean image build may also need access to the container registry
and package index when those layers are not cached.

## MVP scope and limitations

The current implementation has exactly **four checks** and exactly **one
attack-path correlation**:

Checks:

1. `privileged: true` on a service.
2. A writable local bind mount.
3. Explicit high-risk `cap_add` values: `ALL`, `NET_ADMIN`, `SYS_ADMIN`, or
   `SYS_PTRACE`.
4. Explicit host-published service ports through short or long `ports` syntax.

Correlation:

- `PRIVILEGE_TO_SHARED-DATA` when both findings affect the same service.

The following areas are not yet implemented:

- secrets detection in Compose files or environment configuration;
- broader network exposure analysis beyond explicit host-published ports,
  including network policy and service-to-service reachability;
- broader capability and container-hardening analysis beyond the high-risk
  `cap_add` check, including root users and read-only root filesystems;
- CPU, memory, PID, and other resource-limit analysis;
- image vulnerability scanning, provenance, signature, and supply-chain
  analysis;
- runtime inspection of containers or Docker environments;
- generalized attack-path discovery beyond the one deterministic correlation;
- AI-assisted planning or explanation and automated patch generation;
- full Docker Compose schema validation beyond the structure required by the
  current checks.

The analyzer remains configuration-only: it does not run images or Compose
services, execute commands from input files, access host resources, contact
target systems, or use the Docker socket.
