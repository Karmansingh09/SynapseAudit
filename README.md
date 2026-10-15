# SynapseAudit

SynapseAudit is a small, safe, repeatable Docker Compose configuration
analyzer for the OmniRush Frontier Buildathon Systems, Infrastructure &
Cybersecurity track.

It currently checks two configuration risks:

1. `privileged: true` on a service.
2. A writable local bind mount such as `./fixture-data:/app/data:rw`.

When both checks apply to one service, it emits a bounded attack-path
explanation. The explanation is static analysis, not an exploit: SynapseAudit
does not start Compose services, execute configuration content, contact external
systems, read host resources, or access/mount the Docker socket.

## Architecture

- `synapseaudit/analyzer.py` loads YAML with `yaml.safe_load`, runs deterministic
  rules, validates the required Compose structure, and correlates findings in
  stable order.
- `synapseaudit/cli.py` exposes text and JSON output.
- `fixtures/compose.vulnerable.yml` is a deliberately vulnerable but harmless
  local fixture. Its bind source is only `fixtures/fixture-data`.
- `fixtures/compose.remediated.yml` removes privileged mode and makes the bind
  mount read-only.
- `tests/` verifies both rules, the correlation, CLI serialization, and the
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

- Vulnerable fixture: **2 findings** and **1 attack path**.
- Remediated fixture: **0 findings** and **0 attack paths**.
- JSON output contains the same deterministic findings and attack path in a
  machine-readable structure.

The commands analyze YAML only. They do not start Compose services.

## Before/after demonstration

| Check | Vulnerable fixture value | Remediated fixture value | Expected result |
| --- | --- | --- | --- |
| Privileged container mode | `privileged: true` | `privileged: false` | One high-severity finding becomes absent |
| Writable local bind mount | `./fixture-data:/app/data:rw` | `./fixture-data:/app/data:ro` | One medium-severity finding becomes absent |
| Combined result | 2 findings, 1 attack path | 0 findings, 0 attack paths | The correlated path disappears after remediation |

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

## Test

The single project test command is:

```sh
make test
```

It uses Python's standard-library `unittest` runner and the already-installed,
pinned dependency. It does not access the network or Docker.

Malformed YAML and malformed required Compose structures are rejected with an
error rather than being reported as a clean configuration. Unsupported but
valid volume types are ignored by the two current rules.

## Containerized analyzer run

The Dockerfile packages the analyzer and local fixtures. It does not include a
Docker socket or any host-directory mount:

```sh
docker build -t synapseaudit:local .
docker run --rm synapseaudit:local fixtures/compose.vulnerable.yml
```

This runs the analyzer inside the image; it does not run the analyzed Compose
file. The Dockerfile uses the version-tagged `python:3.11.4-slim` base image,
not an immutable digest. Therefore, Python and PyYAML versions are pinned, but
the Docker image is not guaranteed to be bit-for-bit reproducible unless the
base image is later pinned by digest. A clean image build may also need access
to the container registry and package index when those layers are not cached.

## MVP scope and limitations

The current implementation has exactly **two checks** and exactly **one
attack-path correlation**:

Checks:

1. `privileged: true` on a service.
2. A writable local bind mount.

Correlation:

- `PRIVILEGE_TO_SHARED-DATA` when both findings affect the same service.

The following areas are not yet implemented:

- secrets detection in Compose files or environment configuration;
- network exposure analysis, including exposed ports, network policy, and
  service-to-service reachability;
- capability analysis beyond the existing privileged-container check, including
  Linux capabilities, root users, and read-only root filesystems;
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
