# vuln-api

A **deliberately vulnerable Orders API** for the API Security course, Lecture 10
(API Threats, Secure Design, and Observability). It ships with three OWASP API
Security Top 10 (2023) flaws, each next to its fix, and it is fully instrumented
so you can **detect** the attacks: structured JSON logs plus Prometheus metrics.

Deployed in the lab at **https://vuln-api.192.168.50.10.nip.io** (GitOps via
`kse-labs-deployment` -> `applications/vuln-api`).

> This code is intentionally insecure. It is teaching material - do not copy its
> vulnerable paths into anything real.

## The one switch

A single environment variable decides which code path runs:

| `SECURE_MODE` | Behavior |
|---------------|----------|
| `false` (default) | the **vulnerable** code path - the attacks below succeed |
| `true` | the **fixed** code path - the same attacks now fail |

The vulnerable and secure implementations sit side by side in `app.py`, so the
fix is readable, not hidden.

## The three flaws

| OWASP (2023) | Endpoint | Vulnerable | Fixed |
|--------------|----------|------------|-------|
| **API2** Broken Authentication | any | trusts the JWT payload **without** verifying the signature - forge any identity | verifies the Keycloak signature via JWKS (issuer, expiry, `alg`) |
| **API1** Broken Object Level Authz (BOLA) | `GET /api/orders/<id>` | returns **any** order to any caller | the caller must **own** the order, else `403` |
| **API3** Broken Object Property Authz (mass assignment) | `PATCH /api/users/me` | binds the **whole body**, so `{"role":"admin"}` escalates | **allowlist DTO + JSON Schema** (`additionalProperties: false`); unknown/privileged fields are `400` |

## Endpoints

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| GET | `/api/health` | - | reports `secure_mode` |
| GET | `/metrics` | - | Prometheus exposition |
| GET | `/api/me` | Bearer | the caller's profile |
| GET | `/api/orders/<id>` | Bearer | BOLA target |
| PATCH | `/api/users/me` | Bearer | mass-assignment target |

Identities line up with the lab Keycloak users **alice** and **bob** (password ==
username). alice owns orders `o-1001`/`o-1002`; bob owns `o-1003`.

## Detection signals (the observability half)

Every security-relevant event is emitted **twice**: as one structured JSON log
line on stdout (`kubectl logs`) and as a Prometheus counter at `/metrics`.

| Metric | Meaning |
|--------|---------|
| `api_auth_failures_total{reason}` | rejected authentication (secure mode) |
| `api_bola_crossuser_total{outcome}` | a caller asked for an object it does not own (`served` in vuln mode, `denied` in secure mode) - BOLA / sequential-ID probing |
| `api_mass_assignment_total{outcome}` | a PATCH carried fields outside the allowlist (`accepted` vuln, `rejected` secure) |
| `api_privilege_escalation_total` | a caller changed a privileged field (`role`/`credits`) on itself - the mass-assignment exploit landed |
| `api_requests_total{endpoint,method,status}` | all requests |

These are what the practice alerts on with a `PrometheusRule` + Alertmanager.

## Configuration (env)

| Var | Default |
|-----|---------|
| `SECURE_MODE` | `false` |
| `KEYCLOAK_ISSUER_URI` | `https://keycloak.192.168.50.10.nip.io/realms/api-security` |
| `OAUTH_CA_BUNDLE` | unset (TLS verify off - lab uses a self-signed CA) |

## Run the attacks

```bash
pip install -r requirements.txt
python demo/attack.py                    # add LAB_INGRESS_IP off-lab if needed
python demo/attack.py --base https://vuln-api.192.168.50.10.nip.io
```

It forges an unsigned token (broken auth), reads another user's order (BOLA), and
escalates itself via mass assignment - then tells you to re-run against the
`SECURE_MODE=true` deployment to watch each attack fail.

## Run locally

```bash
pip install -r requirements.txt
SECURE_MODE=false gunicorn -b 0.0.0.0:8000 -w 1 --threads 8 app:app
```
