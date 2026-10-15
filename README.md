# SynapseAudit

SynapseAudit is a small, safe, reproducible Docker Compose configuration
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

AI may help plan or explain findings, but rule evaluation and remediation
verification are deterministic code paths.

## Setup

The runtime is pinned to Python 3.11.4 in `.python-version`. The only runtime
dependency is pinned in `requirements.lock`.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --requirement requirements.lock
```

The install step may need package access once. After installation, the test and
analysis commands below are offline and do not start Docker.

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
file. For a clean build, use the pinned base image and `requirements.lock` as
shown above.

## Scope and next step

This vertical slice intentionally supports only the two rules above. A next
safe extension would add more pure rules (for example, sensitive host paths)
with fixture-only tests before adding any broader parser or runtime integration.
