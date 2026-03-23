#!/usr/bin/env python3
"""
Stage 3: Upload the Wiz SCA enrichment JSON (from Stage 2) to Wiz via the
WIN API.  Three-step flow: request upload slot → PUT to S3 → poll status.

Input:  output/wiz-enrichment.json  (from 02_transform_to_wiz.py)
Output: Prints system activity result to stdout.
"""

import argparse
import json
import os
import sys

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))
from wiz_client import get_token, api_url_from_token, graphql, poll_activity

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_FILE = os.path.join(SCRIPT_DIR, "output", "wiz-enrichment.json")

REQUEST_UPLOAD_QUERY = """
query RequestSecurityScanUpload($filename: String!) {
  requestSecurityScanUpload(filename: $filename) {
    upload { id url systemActivityId }
  }
}
"""


def main():
    parser = argparse.ArgumentParser(description="Upload SCA enrichment JSON to Wiz")
    parser.add_argument("--input", default=INPUT_FILE, help="Wiz enrichment JSON from stage 2")
    parser.add_argument("--poll-interval", type=int, default=15, help="Seconds between status polls")
    parser.add_argument("--max-wait", type=int, default=300, help="Max seconds to wait for processing")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"ERROR: {args.input} not found. Run 02_transform_to_wiz.py first.", file=sys.stderr)
        sys.exit(1)

    with open(args.input) as f:
        payload = json.load(f)

    num_findings = sum(
        len(asset.get("vulnerabilityFindings", []))
        for ds in payload.get("dataSources", [])
        for asset in ds.get("assets", [])
    )
    print(f"Uploading {num_findings} findings from {args.input}")

    print("\n[1/3] Authenticating with Wiz...")
    token = get_token()
    api = api_url_from_token(token)
    print(f"  API endpoint: {api}")

    print("\n[2/3] Requesting upload slot...")
    filename = os.path.basename(args.input)
    data = graphql(token, api, REQUEST_UPLOAD_QUERY, {"filename": filename})
    upload = data["data"]["requestSecurityScanUpload"]["upload"]
    upload_id = upload["id"]
    presigned_url = upload["url"]
    activity_id = upload["systemActivityId"]
    print(f"  Upload ID    : {upload_id}")
    print(f"  Activity ID  : {activity_id}")

    print("\n[3/3] Uploading to S3...")
    with open(args.input, "rb") as f:
        resp = requests.put(
            presigned_url,
            data=f,
            headers={"Content-Type": "application/json"},
            timeout=120,
        )
    if resp.status_code != 200:
        print(f"ERROR: S3 upload failed with HTTP {resp.status_code}", file=sys.stderr)
        print(resp.text, file=sys.stderr)
        sys.exit(1)
    print("  S3 upload: OK")

    print(f"\nPolling system activity (every {args.poll_interval}s, max {args.max_wait}s)...")
    result = poll_activity(token, api, activity_id, max_wait=args.max_wait, interval=args.poll_interval)

    status = result["status"]
    info = result.get("statusInfo") or ""
    findings_result = (result.get("result") or {}).get("findings", {})
    unresolved = (result.get("result") or {}).get("unresolvedAssets", {})

    print(f"\n{'='*50}")
    print(f"Status      : {status}")
    if info:
        print(f"Status Info : {info}")
    print(f"Findings    : {findings_result.get('incoming', 0)} incoming, {findings_result.get('handled', 0)} handled")
    if unresolved and unresolved.get("count", 0) > 0:
        print(f"Unresolved  : {unresolved['count']} assets — {unresolved.get('ids', [])}")
    print(f"{'='*50}")

    if status == "SUCCESS":
        print("\nUpload complete. Findings will appear in Wiz within ~10 minutes.")
        print("Run 04_verify_findings.py to confirm they are visible.")
    else:
        print(f"\nUpload did not succeed. Status: {status}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
