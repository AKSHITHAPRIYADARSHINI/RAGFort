"""Controlled local dependency outages; always restore services, never print tokens.

Run only against the synthetic local Compose deployment while browser tests are idle.
The dedicated runtime OIDC client is separate from browser PKCE evidence.
"""

import argparse
import json
import subprocess
import time
from pathlib import Path

import httpx


def runtime_token() -> str:
    values = {}
    for line in Path(".env.keycloak.local").read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip("\"'")
    response = httpx.post(
        "http://localhost:8080/realms/ragfort-local/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "ragfort-runtime-test",
            "username": "acme_employee",
            "password": values["RAGFORT_DEV_USER_PASSWORD"],
        },
        timeout=15,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def query(token: str) -> dict:
    started = time.monotonic()
    response = httpx.post(
        "http://localhost:8000/api/v1/query",
        headers={"Authorization": f"Bearer {token}"},
        json={"query": "What is the ACME tenant verification marker?"},
        timeout=45,
    )
    body = response.json()
    data = body.get("data", {})
    return {
        "status": response.status_code,
        "error": body.get("error", {}).get("code"),
        "answer_status": data.get("answer_status"),
        "answer_present": bool(data.get("answer")),
        "citations": len(data.get("sources", [])),
        "request_id": body.get("request_id"),
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


def compose(*args: str) -> None:
    subprocess.run(["docker", "compose", *args], check=True, capture_output=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute-outages", action="store_true")
    args = parser.parse_args()
    token = runtime_token()
    baseline = query(token)
    print(json.dumps({"baseline": baseline}), flush=True)
    assert baseline["status"] == 200 and baseline["answer_status"] == "grounded"
    if not args.execute_outages:
        return
    for service, allowed_errors in (
        ("postgres", {(503, "AUTHENTICATION_UNAVAILABLE"), (500, "INTERNAL_ERROR")}),
        ("qdrant", {(503, "RAG_RETRIEVAL_UNAVAILABLE")}),
    ):
        try:
            compose("stop", service)
            failed = query(token)
            print(json.dumps({"service": service, "outage": failed}), flush=True)
            # The inherited public PostgreSQL outage path can use its generic
            # safe 500 handler; the release invariant is fail-closed admission.
            assert (failed["status"], failed["error"]) in allowed_errors
            assert not failed["answer_present"] and failed["citations"] == 0
        finally:
            compose("start", service)
            recovered = None
            for _ in range(20):
                try:
                    recovered = query(token)
                    if recovered["status"] == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(1)
            print(json.dumps({"service": service, "recovery": recovered}), flush=True)
            assert recovered and recovered["status"] == 200
            assert recovered["answer_status"] == "grounded" and recovered["citations"] > 0


if __name__ == "__main__":
    main()
