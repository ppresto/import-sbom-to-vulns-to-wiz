#!/usr/bin/env python3
"""
Stage 4: Verify that enriched vulnerability findings are visible on the
target repository branch in Wiz.

Reads the enriched SBOM to know which CVEs to look for, then queries the
Wiz vulnerabilityFindings API.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))
from wiz_client import get_token, api_url_from_token, graphql, get_config

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENRICHED_FILE = os.path.join(SCRIPT_DIR, "output", "enriched-sbom.json")

VULN_QUERY = """
query VulnerabilityFindingsPage($filterBy: VulnerabilityFindingFilters, $first: Int) {
  vulnerabilityFindings(filterBy: $filterBy, first: $first) {
    totalCount
    nodes {
      name severity status detectionMethod dataSourceName
      detailedName version fixedVersion locationPath
    }
  }
}
"""


def main():
    parser = argparse.ArgumentParser(description="Verify uploaded findings on the Wiz branch")
    parser.add_argument("--enriched", default=ENRICHED_FILE, help="Enriched SBOM from stage 1 (to know which CVEs to check)")
    args = parser.parse_args()

    cfg = get_config()

    expected_cves: set[str] = set()
    if os.path.exists(args.enriched):
        with open(args.enriched) as f:
            enriched = json.load(f)
        for finding in enriched.get("findings", []):
            expected_cves.add(finding["cve"])
        print(f"Expecting {len(expected_cves)} unique CVEs from enriched SBOM")
    else:
        print("WARNING: No enriched SBOM found. Will show all 'Custom Integration' findings.")

    print("Authenticating with Wiz...")
    token = get_token()
    api = api_url_from_token(token)

    print(f"Querying vulns on {cfg['repo_name']}:{cfg['repo_branch']}...")
    data = graphql(token, api, VULN_QUERY, {
        "first": 500,
        "filterBy": {"assetId": cfg["asset_id"]},
    })

    nodes = data["data"]["vulnerabilityFindings"]["nodes"]
    total = data["data"]["vulnerabilityFindings"]["totalCount"]
    print(f"Total vulnerability findings on branch: {total}\n")

    custom_findings = [n for n in nodes if n.get("dataSourceName") == "Custom Integration"]
    matched = [n for n in nodes if n["name"] in expected_cves] if expected_cves else custom_findings

    if matched:
        print(f"Found {len(matched)} enrichment findings:\n")
        print(f"  {'CVE':<22} {'Severity':<12} {'Status':<12} {'Detection':<12} {'Package'}")
        print(f"  {'-'*22} {'-'*12} {'-'*12} {'-'*12} {'-'*30}")
        for n in matched:
            print(f"  {n['name']:<22} {n['severity']:<12} {n['status']:<12} {n.get('detectionMethod',''):<12} {n.get('detailedName','')}")
    else:
        print("No enrichment findings visible yet.")
        print("Findings can take up to 10-30 minutes to propagate after upload.")
        print("Re-run this script after waiting.")

    if expected_cves:
        found_cves = {n["name"] for n in matched}
        missing = expected_cves - found_cves
        if missing:
            print(f"\nMISSING ({len(missing)}): {', '.join(sorted(missing))}")
        else:
            print(f"\nAll {len(expected_cves)} expected CVEs confirmed on branch.")


if __name__ == "__main__":
    main()
