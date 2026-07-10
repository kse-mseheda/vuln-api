"""
Deliberately vulnerable API for the API Security course - Lecture 10
(API Threats, Secure Design, and Observability).

One small "Orders" API that ships with three OWASP API Top 10 (2023) flaws, each
with a secure implementation right next to it. A single switch decides which one
runs:

    SECURE_MODE=false  (default)  -> the vulnerable code path, so students exploit it
    SECURE_MODE=true              -> the fixed code path, so the same attack now fails

The three flaws:

  * API2  Broken Authentication      - vuln: trust the JWT payload WITHOUT verifying
                                        the signature, so any identity can be forged.
                                        fix:  verify the Keycloak signature via JWKS.
  * API1  Broken Object Level Authz   - vuln: GET /api/orders/<id> returns any order.
                                        fix:  the caller must own the order.
  * API3  Broken Object Property Authz- vuln: PATCH /api/users/me binds the whole body,
                                        so {"role":"admin"} escalates.
                                        fix:  an allowlist DTO + JSON Schema; unknown or
                                        privileged fields are rejected.

Everything the lecture calls "detection" is wired in too: every security-relevant
event is written as one structured JSON log line, and the same events increment
Prometheus counters exposed at /metrics. That is what the observability part of
the practice alerts on.

Deliberately dependency-light and readable - it is teaching material, not a
framework showcase.
"""
import base64
import json
import logging
import os
import sys
import time
import uuid

import jwt  # PyJWT
import requests
from flask import Flask, g, jsonify, request
from jsonschema import Draft202012Validator
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST

# --- config (env-overridable; defaults target the course lab) ----------------
SECURE_MODE = os.environ.get("SECURE_MODE", "false").lower() in ("1", "true", "yes")
ISSUER = os.environ.get(
    "KEYCLOAK_ISSUER_URI",
    "https://keycloak.192.168.50.10.nip.io/realms/api-security",
)
JWKS_URI = f"{ISSUER}/protocol/openid-connect/certs"
# The lab uses a self-signed internal CA. Point OAUTH_CA_BUNDLE at a CA file to verify;
# otherwise TLS verification of the JWKS fetch is skipped (lab only).
VERIFY = os.environ.get("OAUTH_CA_BUNDLE", False)

app = Flask(__name__)

# --- structured (JSON) logging -----------------------------------------------
# One event per line. Never log tokens, passwords, or secrets - only their shape.
_log = logging.getLogger("vuln-api")
_log.setLevel(logging.INFO)
_h = logging.StreamHandler(sys.stdout)
_h.setFormatter(logging.Formatter("%(message)s"))
_log.addHandler(_h)
_log.propagate = False


def audit(event: str, outcome: str, **fields) -> None:
    """Emit one structured security event as JSON on stdout."""
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": event,
        "outcome": outcome,
        "secure_mode": SECURE_MODE,
        "request_id": getattr(g, "request_id", "-"),
        "client_ip": request.headers.get("X-Forwarded-For", request.remote_addr),
        "method": request.method,
        "path": request.path,
        **fields,
    }
    _log.info(json.dumps(record, separators=(",", ":")))


# --- Prometheus metrics (the detection signals the practice alerts on) --------
AUTH_FAILURES = Counter(
    "api_auth_failures_total", "Rejected authentication attempts", ["reason"])
BOLA_CROSSUSER = Counter(
    "api_bola_crossuser_total",
    "Requests where the caller asked for an object they do not own", ["outcome"])
MASS_ASSIGN = Counter(
    "api_mass_assignment_total",
    "PATCH bodies carrying fields outside the allowlist", ["outcome"])
PRIV_ESCALATION = Counter(
    "api_privilege_escalation_total",
    "Times a caller changed a privileged field (role/credits) on themselves")
REQUESTS = Counter(
    "api_requests_total", "All API requests", ["endpoint", "method", "status"])


# --- demo data (in-memory; resets on restart) --------------------------------
# Identities line up with the lab Keycloak users (password == username).
USERS = {
    "alice": {"username": "alice", "display_name": "Alice",
              "email": "alice@lab.local", "role": "user", "credits": 100},
    "bob":   {"username": "bob", "display_name": "Bob",
              "email": "bob@lab.local", "role": "user", "credits": 50},
}
# Orders belong to a user. alice owns o-1001/o-1002; bob owns o-1003.
ORDERS = {
    "o-1001": {"id": "o-1001", "owner": "alice", "item": "Mechanical keyboard", "total": 89},
    "o-1002": {"id": "o-1002", "owner": "alice", "item": "USB-C hub", "total": 35},
    "o-1003": {"id": "o-1003", "owner": "bob", "item": "Noise-cancelling headphones", "total": 210},
}

# The allowlist for the secure PATCH: only these properties may be client-set.
USER_PATCH_SCHEMA = {
    "type": "object",
    "additionalProperties": False,   # <-- this line is the mass-assignment guard
    "properties": {
        "display_name": {"type": "string", "maxLength": 80},
        "email": {"type": "string", "format": "email", "maxLength": 200},
    },
}
# format_checker makes "format": "email" actually reject bad values (by default
# JSON Schema treats format as an annotation only).
_patch_validator = Draft202012Validator(
    USER_PATCH_SCHEMA, format_checker=Draft202012Validator.FORMAT_CHECKER)


# --- authentication ----------------------------------------------------------
_jwks_keys: dict = {}
_jwks_ts = 0.0


def _signing_key(kid: str):
    """Keycloak signing key for kid, refreshing the JWKS cache as needed."""
    global _jwks_ts
    if kid not in _jwks_keys or (time.time() - _jwks_ts) > 300:
        r = requests.get(JWKS_URI, verify=VERIFY, timeout=8)
        r.raise_for_status()
        fresh = {}
        for k in r.json().get("keys", []):
            cls = {"RSA": jwt.algorithms.RSAAlgorithm,
                   "EC": jwt.algorithms.ECAlgorithm}.get(k.get("kty"))
            if cls and k.get("kid"):
                try:
                    fresh[k["kid"]] = cls.from_jwk(json.dumps(k))
                except Exception:
                    pass
        _jwks_keys.clear()
        _jwks_keys.update(fresh)
        _jwks_ts = time.time()
    return _jwks_keys.get(kid)


class AuthError(Exception):
    def __init__(self, reason: str):
        self.reason = reason


def _claims_insecure(token: str) -> dict:
    """VULN (API2): decode the JWT payload WITHOUT verifying the signature.

    This is the classic broken-authentication bug: the payload is base64 - anyone
    can craft a token with preferred_username=alice (or admin) and this trusts it.
    """
    try:
        payload_b64 = token.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
    except Exception:
        raise AuthError("malformed")
    if not payload.get("preferred_username"):
        raise AuthError("no_subject")
    return payload


def _claims_secure(token: str) -> dict:
    """FIX (API2): verify the Keycloak-signed JWT (signature, issuer, expiry)."""
    try:
        kid = jwt.get_unverified_header(token).get("kid")
        key = _signing_key(kid)
        if key is None:
            raise ValueError(f"unknown signing key kid={kid}")
        return jwt.decode(token, key, algorithms=["RS256", "ES256", "PS256"],
                          issuer=ISSUER, options={"verify_aud": False})
    except Exception as e:
        raise AuthError(f"invalid_token:{type(e).__name__}")


def current_user() -> dict:
    """Resolve the caller from the Authorization header, honoring SECURE_MODE.

    Returns a live USERS record (creating a bare one for identities the API has
    not seen, so a valid Keycloak user is always accepted).
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise AuthError("no_bearer")
    token = auth[len("Bearer "):].strip()
    claims = _claims_secure(token) if SECURE_MODE else _claims_insecure(token)
    username = claims.get("preferred_username")
    if username not in USERS:
        USERS[username] = {"username": username, "display_name": username,
                           "email": claims.get("email", ""), "role": "user", "credits": 0}
    return USERS[username]


# --- request plumbing --------------------------------------------------------
@app.before_request
def _assign_request_id():
    g.request_id = request.headers.get("X-Request-Id", uuid.uuid4().hex[:12])


@app.after_request
def _count_request(resp):
    if request.endpoint and request.endpoint != "metrics":
        REQUESTS.labels(request.endpoint, request.method, str(resp.status_code)).inc()
    return resp


def _deny_auth(err: AuthError):
    AUTH_FAILURES.labels(err.reason).inc()
    audit("auth_failure", "deny", reason=err.reason)
    return jsonify(error="unauthorized", reason=err.reason), 401


# --- endpoints ---------------------------------------------------------------
@app.get("/api/health")
def health():
    return jsonify(status="UP", service="vuln-api", secure_mode=SECURE_MODE)


@app.get("/metrics")
def metrics():
    return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}


@app.get("/api/me")
def me():
    try:
        user = current_user()
    except AuthError as e:
        return _deny_auth(e)
    return jsonify(user)


@app.get("/api/orders/<order_id>")
def get_order(order_id):
    """API1 BOLA. VULN: any authenticated caller reads any order.
    FIX: the caller must own it."""
    try:
        user = current_user()
    except AuthError as e:
        return _deny_auth(e)

    order = ORDERS.get(order_id)
    if not order:
        return jsonify(error="not_found"), 404

    owns = order["owner"] == user["username"]
    if not owns:
        # This is an attack indicator in BOTH modes - one caller reaching for
        # objects that are not theirs (sequential-ID / BOLA probing).
        if SECURE_MODE:
            BOLA_CROSSUSER.labels("denied").inc()
            audit("bola_attempt", "deny", subject=user["username"],
                  object=order_id, object_owner=order["owner"])
            return jsonify(error="forbidden"), 403
        BOLA_CROSSUSER.labels("served").inc()
        audit("bola_attempt", "served", subject=user["username"],
              object=order_id, object_owner=order["owner"])

    return jsonify(order)


@app.patch("/api/users/me")
def update_me():
    """API3 mass assignment. VULN: merge the whole body into the user record.
    FIX: allowlist + JSON Schema; reject unknown/privileged fields."""
    try:
        user = current_user()
    except AuthError as e:
        return _deny_auth(e)
    body = request.get_json(silent=True) or {}

    if SECURE_MODE:
        # FIX: validate against the allowlist schema; additionalProperties:false
        # rejects role/credits/isAdmin and anything else not explicitly allowed.
        errors = sorted(_patch_validator.iter_errors(body), key=lambda e: e.path)
        if errors:
            rejected = sorted({(list(e.path) or [e.validator])[0] for e in errors})
            MASS_ASSIGN.labels("rejected").inc()
            audit("mass_assignment", "reject", subject=user["username"],
                  rejected_fields=[str(f) for f in rejected])
            return jsonify(error="invalid_body",
                           detail=[e.message for e in errors]), 400
        for field in ("display_name", "email"):
            if field in body:
                user[field] = body[field]
        audit("profile_update", "allow", subject=user["username"],
              fields=sorted(body.keys()))
        return jsonify(user)

    # VULN: blind merge. {"role":"admin","credits":999999} escalates.
    privileged = {"role", "credits", "username"} & set(body.keys())
    user.update(body)
    if privileged:
        PRIV_ESCALATION.inc()
        MASS_ASSIGN.labels("accepted").inc()
        audit("privilege_escalation", "served", subject=user["username"],
              changed_fields=sorted(privileged), new_role=user.get("role"),
              new_credits=user.get("credits"))
    else:
        audit("profile_update", "allow", subject=user["username"],
              fields=sorted(body.keys()))
    return jsonify(user)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
