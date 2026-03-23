#!/usr/bin/env python3
"""
Stage 5: Delete (reset) enriched findings from the Wiz branch.

Uploads an enrichment file with the SAME dataSource.id but an EMPTY
vulnerabilityFindings array.  Wiz replaces the previous batch with nothing,
effectively removing the findings.  Useful for resetting a demo.
"""

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))
from wiz_client import get_token, api_url_from_token, graphql, poll_activity, get_config

REQUEST_UPLOAD_QUERY = """
query RequestSecurityScanUpload($filename: String!) {
  requestSecurityScanUpload(filename: $filename) {
    upload { id url systemActivityId }
  }
}
"""


def main():
    parser = argparse.ArgumentParser(description="Delete enriched findings from Wiz (demo reset)")
    parser.add_argument("--poll-interval", type=int, default=15)
    parser.add_argument("--max-wait", type=int, default=300)
    args = parser.parse_args()

    cfg = get_config()
    analysis_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    empty_payload = {
        "integrationId": cfg["integration_id"],
        "dataSources": [
            {
                "id": cfg["datasource_id"],
                "analysisDate": analysis_date,
                "assets": [
                    {
                        "details": {
                            "repositoryBranch": {
                                "assetId": cfg["asset_id"],
                                "assetName": f"{cfg['repo_name']}:{cfg['repo_branch']}",
                                "branchName": cfg["repo_branch"],
                                "repository": {
                                    "name": cfg["repo_name"],
                                    "url": cfg["repo_url"],
                                },
                                "vcs": cfg["vcs_type"],
                            }
                        },
                        "vulnerabilityFindings": [],
                    }
                ],
            }
        ],
    }

    print(f"Resetting findings for dataSource: {cfg['datasource_id']}")
    print(f"  Target: {cfg['repo_name']}:{cfg['repo_branch']}")
    print(f"  Sending empty vulnerabilityFindings array...\n")

    token = get_token()
    api = api_url_from_token(token)

    data = graphql(token, api, REQUEST_UPLOAD_QUERY, {"filename": "delete-enrichment.json"})
    upload = data["data"]["requestSecurityScanUpload"]["upload"]
    activity_id = upload["systemActivityId"]
    presigned_url = upload["url"]
    print(f"  Activity ID: {activity_id}")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        json.dump(empty_payload, tmp)
        tmp_path = tmp.name

    try:
        with open(tmp_path, "rb") as f:
            resp = requests.put(presigned_url, data=f, headers={"Content-Type": "application/json"}, timeout=120)
        if resp.status_code != 200:
            print(f"ERROR: S3 upload failed with HTTP {resp.status_code}", file=sys.stderr)
            sys.exit(1)
        print("  S3 upload: OK")
    finally:
        os.unlink(tmp_path)

    print(f"\nPolling system activity...")
    result = poll_activity(token, api, activity_id, max_wait=args.max_wait, interval=args.poll_interval)

    status = result["status"]
    print(f"\nStatus: {status}")
    if status == "SUCCESS":
        print("Findings deleted. They will disappear from Wiz within ~10 minutes.")
        print("Run 04_verify_findings.py after waiting to confirm removal.")
    else:
        info = result.get("statusInfo", "")
        print(f"Delete may not have succeeded. Info: {info}", file=sys.stderr)


if __name__ == "__main__":
    main()
