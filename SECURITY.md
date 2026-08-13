# Security policy

## Reporting a vulnerability

Report vulnerabilities privately via GitHub Security Advisories on this
repository, with a description of the issue, reproduction steps, and (if
possible) a suggested fix. Do **not** open a public issue. You will receive
an acknowledgement within 3 business days and a remediation timeline within
10 business days.

Please provide:

- Affected version / commit SHA
- Steps to reproduce
- Impact assessment (confidentiality / integrity / availability)
- Any proof-of-concept code

## Scope

In scope:

- Remote code execution or memory safety issues in the C++ code.
- Secret leakage via logs, error responses, or crash dumps.
- Bypasses of any request-gating middleware.
- Supply-chain risks in dependencies declared in `vcpkg.json` or `CMakeLists.txt`.

Out of scope:

- Issues in third-party libraries already reported upstream (please link to the
  CVE; we will bump the version).
- Denial-of-service via unbounded client input against a dev deployment
  behind no reverse proxy.

## Disclosure

We follow a **90-day coordinated disclosure** window from the acknowledgement
date. If a fix is not shipped by then, we will work with the reporter on a
mutually acceptable extension. Credits in the release notes on request.

## Failure-mode policies (fail-open vs fail-closed)

When the dependencies that back security middleware are unavailable, each
piece either **fails open** (let the request through) or **fails closed**
(reject the request). Operators must understand which is which to plan
incidents — a Redis outage is not the same as a database outage.

| Middleware             | When it fails | Behavior  | Why |
|------------------------|---------------|-----------|-----|
| Content-type gate      | Non-JSON mutation body | **Fail closed** (415) | A malformed body must not reach a handler that assumes JSON. |
| Cache (read path)      | Redis down | **Fail open** (treat as miss, hit DB) | Cache is an optimization, not a correctness layer. |
| Cache (write path)     | Redis down | Skip silently (warn) | Same. |
| Database (any)         | Postgres down | **Fail closed** | The only authoritative store — there's no safe degraded mode. |
| Migrations on startup  | Postgres down | Refuse to start | A misapplied schema is worse than no service. |
| Tracing / metrics      | OTLP endpoint down | Drop spans/metrics, keep serving | Observability is non-blocking by design. |

**Operational implication:** during a Redis outage the service keeps serving
from Postgres with cache misses; a Postgres outage takes it out of rotation.
Anything added later that gates requests on Redis must declare its own
fail-open/fail-closed choice in this table.

## Hardening checklist for deployments

Before shipping this template to production:

- [ ] `app.env=production` so the boot-time config warnings are armed.
- [ ] `docs.enabled=false` (no public Swagger UI).
- [ ] `DATABASE_REQUIRE_SECURE_PASSWORD=true` with a strong `DATABASE_PASSWORD`.
- [ ] Secrets sourced from External Secrets / Vault, not inline in values.yaml.
- [ ] `networkPolicy.enabled=true` with selectors tuned for the cluster.
- [ ] TLS termination at the ingress (cert-manager or equivalent).
- [ ] Image scan (Trivy / Snyk) blocking CRITICAL.
- [ ] PrometheusRule alerts wired to pager.
