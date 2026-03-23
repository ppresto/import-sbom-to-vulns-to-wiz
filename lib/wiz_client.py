"""Shared Wiz API client: authentication, token management, GraphQL helper."""

import base64
import json
import os
import sys
import time

import requests
from dotenv import load_dotenv

ENV_LOADED = False


def load_env():
    """Load .env file once. Falls back to env vars already exported in the shell."""
    global ENV_LOADED
    if ENV_LOADED:
        return
    dotenv_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    if os.path.exists(dotenv_path):
        load_dotenv(dotenv_path, override=False)
    ENV_LOADED = True


def _require_env(key: str) -> str:
    load_env()
    val = os.environ.get(key, "").strip()
    if not val or val.startswith("your-"):
        print(f"ERROR: {key} is not set. Copy .env.example → .env and fill it in.", file=sys.stderr)
        sys.exit(1)
    return val


def get_token() -> str:
    """Authenticate with Wiz OAuth and return a bearer token."""
    client_id = _require_env("WIZ_CLIENT_ID")
    client_secret = _require_env("WIZ_CLIENT_SECRET")
    token_url = os.environ.get("WIZ_TOKEN_URL", "https://auth.app.wiz.io/oauth/token").strip()

    resp = requests.post(
        token_url,
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "audience": "wiz-api",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )
    resp.raise_for_status()
    token = resp.json()["access_token"]
    return token


def api_url_from_token(token: str) -> str:
    """Extract the data center from the JWT and build the GraphQL endpoint."""
    parts = token.split(".")
    payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))
    dc = claims.get("dc", "us20")
    return f"https://api.{dc}.app.wiz.io/graphql"


def graphql(token: str, api: str, query: str, variables: dict | None = None) -> dict:
    """Execute a GraphQL query against the Wiz API."""
    body: dict = {"query": query}
    if variables:
        body["variables"] = variables
    resp = requests.post(
        api,
        json=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        timeout=60,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("errors"):
        msgs = [e.get("message", str(e)) for e in data["errors"]]
        print(f"GraphQL errors: {'; '.join(msgs)}", file=sys.stderr)
        if not data.get("data"):
            sys.exit(1)
    return data


def poll_activity(token: str, api: str, activity_id: str, max_wait: int = 300, interval: int = 15) -> dict:
    """Poll systemActivity until it reaches a terminal status or timeout."""
    query = """
    query SystemActivity($id: ID!) {
      systemActivity(id: $id) {
        id status statusInfo
        result {
          ...on SystemActivityEnrichmentIntegrationResult {
            dataSources { incoming handled }
            findings   { incoming handled }
            unresolvedAssets { count ids }
          }
        }
      }
    }
    """
    deadline = time.time() + max_wait
    while time.time() < deadline:
        data = graphql(token, api, query, {"id": activity_id})
        activity = (data.get("data") or {}).get("systemActivity")
        if not activity:
            print(f"  Activity {activity_id} not visible yet, waiting...")
            time.sleep(interval)
            continue

        status = activity["status"]
        print(f"  Status: {status}")
        if status in ("SUCCESS", "FAILURE", "SKIPPED"):
            return activity
        time.sleep(interval)

    print("ERROR: Timed out waiting for system activity to complete.", file=sys.stderr)
    sys.exit(1)


def get_config() -> dict:
    """Return all pipeline config values from env."""
    load_env()
    return {
        "integration_id": _require_env("WIZ_INTEGRATION_ID"),
        "asset_id": _require_env("REPO_ASSET_ID"),
        "repo_name": _require_env("REPO_NAME"),
        "repo_branch": _require_env("REPO_BRANCH"),
        "repo_url": _require_env("REPO_URL"),
        "vcs_type": os.environ.get("VCS_TYPE", "GitHub").strip(),
        "datasource_id": _require_env("DATASOURCE_ID"),
    }
