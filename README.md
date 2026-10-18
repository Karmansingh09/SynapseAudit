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
an exploit: the local analyzer does not start Compose services, execute
configuration content, read host resources, or access/mount the Docker socket.
The optional GitHub flow contacts only the GitHub API, fetches bounded
allowlisted blobs, and never executes repository content.

## Architecture

- `synapseaudit/analyzer.py` loads YAML with `yaml.safe_load` and uses PyYAML
  source marks for repository findings, runs deterministic rules, validates the
  required Compose structure, and correlates findings in stable order.
- `synapseaudit/cli.py` exposes text and JSON output.
- `synapseaudit/web.py` serves a loopback-only public landing page at `/`, the
  functional dashboard at `/console`, an allowlisted fixture-analysis API, and
  a bounded in-memory upload-analysis API using the existing analyzer directly.
  It also exposes optional GitHub App installation, session, repository, and
  branch metadata routes plus the bounded Phase 2 repository scan endpoint.
- `synapseaudit/github.py` contains the optional server-side GitHub App flow,
  expiring in-memory sessions, one-time authorization state, CSRF protection,
  installation-token handling, immutable-SHA tree/blob fetching, scan budgets,
  skipped-file reporting, and read-only repository/branch metadata access.
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

The runtime is pinned to Python 3.11.4 in `.python-version`. Runtime
dependencies, including `PyYAML==6.0.2` and the server-side `cryptography`
package used for GitHub App JWT signing, are pinned in `requirements.lock`. These pins
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
live analyzer findings, severity counts, evidence, explanation, potential impact,
remediation, limitations, the bounded attack-path explanation, and a before/after
comparison computed from both fixture reports. It also accepts one user-provided Compose YAML file through the
**Upload YAML** control. Supported filenames end in `.yml` or `.yaml`; the
server validates the content itself, accepts files up to 1 MiB with a small
bounded multipart envelope, analyzes them in memory, and never persists the
upload. Uploaded results are clearly labeled and shown separately from the
built-in vulnerable-to-remediated fixture baseline. Uploading a file does not
fabricate a comparison with that file; the comparison always identifies the two
built-in fixtures used. Use `Ctrl-C` to stop the local server.

The API is intentionally narrow:

```sh
curl http://127.0.0.1:8765/api/analyze?fixture=vulnerable
curl http://127.0.0.1:8765/api/analyze?fixture=remediated
curl -F "compose_file=@path/to/compose.yml" http://127.0.0.1:8765/api/analyze-upload
```

When the optional GitHub App is configured and connected, the dashboard sends a
CSRF-protected `POST /api/github/scan` JSON request containing only `owner`,
`repository`, and `branch`. The server re-checks installation access, resolves
the branch to a commit SHA, fetches the recursive tree at that SHA, and fetches
only supported Compose blobs. Tokens, private keys, blob content, and GitHub
URLs are never accepted from or returned to the browser.

The fixture endpoint accepts only the two repository-owned fixture IDs. The
upload endpoint accepts exactly one multipart field named `compose_file`,
requires UTF-8 YAML with a non-empty `services` mapping, and returns the same
`findings`/`attack_paths` report shape with structured explanation, impact,
evidence, remediation, and limitations for each finding. Missing fields, malformed multipart,
invalid YAML, invalid Compose structure, invalid UTF-8, and oversized requests
or files are rejected without writing a file. The server binds to `127.0.0.1`, accepts
no arbitrary paths or URLs, calls the analyzer directly, and never runs
Compose, shell commands, images, or Docker API operations. Review uploaded
configuration files before analysis and remove secrets first; Compose files can
contain credentials, tokens, and other sensitive values. The dashboard uses
DOM text rendering for analyzer-provided strings and does not make security
decisions with AI.

## Optional GitHub App connection and repository scan (Phases 1–2)

The dashboard includes an optional **Connect GitHub** control. Phase 1 supports
GitHub App installation authorization, accessible repository listing, and branch
listing. Phase 2 enables **Start security scan** after a repository and branch
are selected.

Configure the GitHub App only on the server. Copy `.env.example` as a reference
and provide the values through a deployment secret mechanism or process
environment; do not commit a private key. The required values are:

- `SYNAPSEAUDIT_GITHUB_APP_ID`: numeric GitHub App ID;
- `SYNAPSEAUDIT_GITHUB_APP_SLUG`: GitHub App slug;
- `SYNAPSEAUDIT_GITHUB_PRIVATE_KEY_FILE`: server-readable private-key file path;
- `SYNAPSEAUDIT_GITHUB_CALLBACK_URL`: public HTTPS callback URL configured in
  the GitHub App settings. Its exact path must be `/api/github/callback`;
- `SYNAPSEAUDIT_DASHBOARD_PASSWORD`: server-side access control password. Required whenever
  GitHub App integration is enabled; optional for local-only development.

Run the configuration preflight before starting the dashboard:

```sh
make check-github-config
```

With all GitHub variables and the dashboard password blank, the command reports that local-only mode is
active and exits successfully. Partial or invalid configuration exits nonzero and
reports only safe validation details; it never prints environment values, passwords, private
key paths, or private-key contents.

The GitHub App should request only **read-only repository metadata** and
**read-only repository contents** permissions. Users select accessible
repositories on GitHub's installation screen; SynapseAudit does not collect a
GitHub password. Installation tokens and private keys remain server-side and
are never returned to the browser or written to logs. Private key files
(`*.pem`, `*.key`, `*.pk8`) and `private-keys/` directories are ignored by
`.gitignore` to prevent accidental commits. Note that `.gitignore` prevents
untracked files from being added, but does not retroactively untrack files
already committed to Git; never commit real secrets or private keys to source control.

GitHub App callbacks cannot reach a process that is directly reachable only at
`127.0.0.1`. A real deployment needs a public HTTPS callback endpoint whose path
is exactly `/api/github/callback`, usually with a reverse proxy forwarding to the
loopback-bound application. Keep port `8765` private: expose only the proxy's
HTTPS listener and forward it to `http://127.0.0.1:8765`. Do not expose port
`8765` publicly and do not use an unapproved public tunnel. Leave the GitHub
variables blank to keep the existing local-only mode; local fixture and YAML
upload analysis do not require external access.

### Dashboard authentication and access control

When preparing for public reverse proxy or GitHub App deployment, application-level access control protects the console, analysis APIs, upload endpoints, and GitHub integration:

1. **Dashboard password requirement**: Whenever GitHub integration is enabled (any GitHub configuration variable is set), `SYNAPSEAUDIT_DASHBOARD_PASSWORD` is strictly required. Startup and `make check-github-config` fail closed if it is missing or empty.
2. **Local-only development**: When no GitHub variables and no dashboard password are set, SynapseAudit runs unauthenticated for local development, binding strictly to loopback (`127.0.0.1`).
3. **HTTP Basic Authentication**: When `SYNAPSEAUDIT_DASHBOARD_PASSWORD` is configured, all protected routes require RFC 7617 HTTP Basic Authentication (`Authorization: Basic <base64>`). Any username may be provided (e.g. `admin`); authentication validates the password using constant-time comparison (`secrets.compare_digest`). Browsers cache HTTP Basic credentials per-origin and send them on subsequent requests automatically. Direct access to `127.0.0.1:8765` cannot bypass authentication.
4. **Strict route allowlist**:
   - **Public GET routes**: `GET /` (landing page), `GET /static/dashboard.js`, and `GET /api/github/callback`.
   - **Protected routes**: `/console`, `/api/analyze`, `/api/analyze-upload`, `/api/github/status`, `/api/github/connect`, `/api/github/repositories`, `/api/github/repositories/<owner>/<repo>/branches`, and `/api/github/scan`.
   - **Deny-by-default**: Any unmapped route or unexpected HTTP method is rejected (401 Unauthorized, 404 Not Found, or 405 Method Not Allowed).
5. **GitHub callback route bypass and security guarantees**: `GET /api/github/callback` intentionally bypasses the HTTP Basic challenge so that external browser redirects from GitHub App installation can complete. The callback endpoint does not expose any analysis data or management actions. It strictly validates:
   - Presence of an active session cookie (`synapseaudit_session`).
   - Matching one-time cryptographically secure `state` parameter generated during `/api/github/connect`.
   - Complete installation parameters.
   - Upon successful callback, the session cookie is rotated immediately (`HttpOnly`, `SameSite=Lax`, `Secure`) and the one-time `state` is invalidated to prevent session fixation and replay attacks.
6. **In-memory failed authentication rate limiting**:
   - `AuthRateLimiter` tracks failed authentication attempts per client IP.
   - If a client accumulates 5 failed attempts within 60 seconds, further attempts from that IP are blocked for 300 seconds (5 minutes) with HTTP `429 Too Many Requests` and a `Retry-After` header.
   - Rate limiting state is in-memory, bounded to 1,000 unique client IPs with LRU eviction, and resets on process restart.
7. **Trusted-proxy client-IP resolution (`SYNAPSEAUDIT_TRUSTED_PROXIES`)**:
   - By default, `SYNAPSEAUDIT_TRUSTED_PROXIES` is empty: all requests use the direct TCP socket peer IP (`127.0.0.1`), and all `X-Forwarded-*` headers are strictly ignored. This prevents client IP spoofing in direct connections.
   - When deployed behind a reverse proxy or local tunnel (e.g. Caddy, Nginx, Tailscale Funnel), all requests reach loopback with socket peer `127.0.0.1`. If `SYNAPSEAUDIT_TRUSTED_PROXIES` was not configured, an attacker's failed logins would lock out `127.0.0.1`, creating a denial-of-service against all legitimate users.
   - Configure `SYNAPSEAUDIT_TRUSTED_PROXIES=127.0.0.1,::1` (or the proxy's IP/CIDR) to enable secure header extraction:
     - The proxy socket peer must explicitly match an entry in `SYNAPSEAUDIT_TRUSTED_PROXIES`.
     - The `X-Forwarded-For` chain is parsed **right-to-left**, discarding only explicitly trusted proxy IPs. The first untrusted IP encountered is resolved as the authentic client IP.
     - Spoofing the leftmost entry (e.g. `X-Forwarded-For: 1.1.1.1`) is ineffective because the reverse proxy appends the real client IP to the right, and SynapseAudit reads from the right.
     - Malformed tokens, injection attempts, and empty segments fail closed and fall back safely to the socket peer IP.
   - Configuration can also be passed via the CLI argument `--trusted-proxies "127.0.0.1,::1"`.
8. **Reverse proxy and TLS requirements**:
   - HTTP Basic Authentication credentials are base64-encoded, not encrypted. Basic Auth alone does **not** protect against eavesdropping over plaintext HTTP.
   - Any public deployment **must** terminate TLS/HTTPS at the external boundary and proxy to `http://127.0.0.1:8765`.
   - The application binds exclusively to loopback (`127.0.0.1`). Never bind directly to `0.0.0.0` or expose port 8765 directly to untrusted networks.
   - SynapseAudit does not read or trust `Host` headers for redirects, ensuring immunity to host header poisoning.

### Deployment options for GitHub App integration

Receiving GitHub App installation callbacks requires a publicly routable HTTPS endpoint forwarding to the local dashboard. Three primary architectures are compared:

| Deployment Option | TLS Termination | Security Considerations & Boundary Controls | Suitability |
| :--- | :--- | :--- | :--- |
| **Tailscale Funnel** | Tailscale Edge (`*.ts.net`) | **Pros**: Quick zero-config TLS for local testing.<br>**Cons**: macOS sleep, lid closure, Wi-Fi drops, and IP renewal break public callback availability. Requires strict dashboard authentication (`SYNAPSEAUDIT_DASHBOARD_PASSWORD`) and `SYNAPSEAUDIT_TRUSTED_PROXIES=127.0.0.1,::1` to prevent DoS. | Temporary, attended local development only. |
| **Cloudflare Tunnel (`cloudflared`)** | Cloudflare Edge | **Pros**: Cloudflare Zero Trust / Access can enforce MFA and identity at the edge for `/console` while allowing `/api/github/callback` to pass through.<br>**Cons**: Still dependent on host machine uptime if run on a laptop. | Recommended for secure remote access without port forwarding. |
| **Cloud VM / Container (Caddy / Nginx)** | Reverse proxy (Let's Encrypt) | **Pros**: 24/7 uptime, stable IP/DNS, isolated compute environment, defense-in-depth edge rate limiting and path routing.<br>**Cons**: Requires infrastructure management. | Recommended for production and team deployments. |


### Private-key storage on macOS

When the dashboard process runs on a Mac, keep the downloaded GitHub App private
key outside the repository in a user-owned directory. The following commands
create the directory and apply owner-only permissions; they do not generate or
print a key:

```sh
KEY_DIR="$HOME/Library/Application Support/SynapseAudit/secrets"
mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"
# Place the GitHub App key at "$KEY_DIR/app.pem" using the GitHub settings UI.
chmod 600 "$KEY_DIR/app.pem"
export SYNAPSEAUDIT_GITHUB_PRIVATE_KEY_FILE="$KEY_DIR/app.pem"
export SYNAPSEAUDIT_DASHBOARD_PASSWORD="replace-with-a-secure-password"
make check-github-config
```

Do not commit the key or put its contents in browser code, URLs, logs, reports,
or source control. The public HTTPS deployment endpoint is still required for a
GitHub callback; a loopback-only Mac process cannot receive that callback by
itself.

All repository requests are server-authorized against the current installation
on every request. Sessions expire, authorization state is one-use, and revoked
or expired installation access clears the connection. The scan re-checks the
selected repository, resolves the selected branch to one immutable commit SHA,
fetches the Git tree at that SHA, and fetches only blob entries whose exact
basename is one of:

- `compose.yml`
- `compose.yaml`
- `docker-compose.yml`
- `docker-compose.yaml`

Nested paths are allowed and are returned as repository-relative paths. All
other files, directories, symlinks, submodules, unsafe paths, malformed blobs,
and invalid Compose YAML are reported as skipped with a reason. No repository
archives, source-code files, Dockerfiles, Kubernetes, Terraform, GitHub
Actions, package manifests, websites, or runtime behavior are analyzed.

Each supported file is analyzed independently by the existing four deterministic
Compose rules. Findings include the repository-relative file path and YAML mark
line range when available. Correlations never combine findings from different
files. A result includes the repository, branch, immutable commit SHA, status,
explicit `github_repository` source and analysis scope, per-file reports,
skipped-file details and counts, budget limits, and usage. Blob content and
credentials are not included in the result.

`status` is `complete` only when the scan finishes within all budgets and at
least one supported file is analyzed. `no_supported_files` is not a clean
result. `limited` means a documented tree, file, byte, duration, response,
pagination, or request budget stopped the scan; limited results must not be
interpreted as clean.

### Phase 2 scan budgets

The defaults are configurable through the server environment or `.env.example`:

| Variable | Default | Meaning |
| --- | ---: | --- |
| `SYNAPSEAUDIT_SCAN_MAX_TREE_ENTRIES` | `10000` | Maximum Git tree entries considered |
| `SYNAPSEAUDIT_SCAN_MAX_SUPPORTED_FILES` | `20` | Maximum supported Compose blobs per scan |
| `SYNAPSEAUDIT_SCAN_MAX_FILE_BYTES` | `1048576` | Maximum decoded bytes per blob |
| `SYNAPSEAUDIT_SCAN_MAX_TOTAL_BYTES` | `8388608` | Maximum bytes downloaded across the scan |
| `SYNAPSEAUDIT_SCAN_MAX_DURATION_SECONDS` | `30` | Total wall-clock scan budget |
| `SYNAPSEAUDIT_SCAN_MAX_HTTP_RESPONSE_BYTES` | `2097152` | Maximum one GitHub JSON response body |
| `SYNAPSEAUDIT_SCAN_MAX_API_PAGES` | `10` | Maximum paginated API pages |
| `SYNAPSEAUDIT_SCAN_MAX_API_REQUESTS` | `40` | Maximum GitHub API requests |
| `SYNAPSEAUDIT_SCAN_MAX_SKIPPED_DETAILS` | `100` | Maximum detailed skipped entries returned |
| `SYNAPSEAUDIT_SCAN_MAX_CONCURRENT` | `4` | Maximum simultaneous scans globally and one per session |
| `SYNAPSEAUDIT_SCAN_MAX_ANALYSIS_SECONDS` | `5` | Maximum isolated YAML analysis time per file |
| `SYNAPSEAUDIT_SCAN_MAX_YAML_DEPTH` | `64` | Maximum YAML nesting depth |
| `SYNAPSEAUDIT_SCAN_MAX_YAML_EVENTS` | `20000` | Maximum YAML parser events |
| `SYNAPSEAUDIT_SCAN_MAX_YAML_ALIASES` | `128` | Maximum YAML aliases |
| `SYNAPSEAUDIT_SCAN_MAX_YAML_SCALAR_CHARS` | `1048576` | Maximum scalar characters |
| `SYNAPSEAUDIT_SCAN_MAX_YAML_COLLECTION_ITEMS` | `2000` | Maximum items in one YAML collection |
| `SYNAPSEAUDIT_SCAN_MAX_SERVICES` | `200` | Maximum Compose services |
| `SYNAPSEAUDIT_SCAN_MAX_SERVICE_ITEMS` | `1000` | Maximum `cap_add`, `ports`, or `volumes` entries per service |

The scan uses bounded ten-second HTTP timeouts, no automatic retries, no API
redirects, one non-queued global/per-session admission limit, and one shared
budget across authorization-token refresh, repository verification, branch
resolution, tree fetching, blob fetching, and analysis. Environment values are
clamped to hard upper bounds; they cannot disable the resource protections.
Each Compose file is analyzed in a fresh isolated process that is terminated if
it exceeds its per-file deadline. Structural YAML preflight limits run before
materialization, and timeout or worker failures produce an incomplete scan.

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
Therefore, Python and application dependency versions are pinned, but the Docker image is not
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
- This is a deterministic, hypothetical configuration-risk correlation, not
  proof of exploitation or a generalized attack graph.

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
- full Docker Compose schema validation beyond the structure and field types
  required by the current checks.

The analyzer remains configuration-only: it does not run images or Compose
services, execute commands from input files, access host resources, contact
target systems, or use the Docker socket.
