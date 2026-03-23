#!/usr/bin/env python3
"""
Stage 2: Transform the enriched SBOM (from Stage 1) into Wiz's SCA
Application Vulnerability Findings JSON schema, ready for API upload.

Input:  output/enriched-sbom.json  (from 01_enrich_sbom.py)
Output: output/wiz-enrichment.json
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))
from wiz_client import get_config

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_FILE = os.path.join(SCRIPT_DIR, "output", "enriched-sbom.json")
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "output", "wiz-enrichment.json")

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}


def normalize_severity(sev: str) -> str:
    titled = sev.strip().title()
    if titled in VALID_SEVERITIES:
        return titled
    mapping = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Informational"}
    return mapping.get(sev.strip().lower(), "Medium")


def build_finding(f: dict) -> dict:
    """Convert one enriched finding dict into a Wiz vulnerabilityFinding."""
    cve = f["cve"]
    pkg = f["package_name"]
    ver = f["package_version"]

    finding: dict = {
        "id": f"{cve}##{pkg}##{ver}",
        "name": cve,
        "description": f.get("description", "")[:1000],
        "severity": normalize_severity(f.get("severity", "Medium")),
        "externalDetectionSource": "Library",
        "externalFindingLink": f.get("link", ""),
        "remediation": f"Upgrade {pkg} to {f['fixed_version']}." if f.get("fixed_version") else f"Review {cve} for remediation guidance.",
        "targetComponent": {
            "library": {
                "name": pkg,
                "version": ver,
                "filePath": f.get("file_path", ""),
            }
        },
    }

    if f.get("fixed_version"):
        finding["targetComponent"]["library"]["fixedVersion"] = f["fixed_version"]

    lang = f.get("language", "")
    if lang and lang != "Other":
        finding["scaFinding"] = {
            "codeLanguage": lang,
            "reachability": "Unknown",
        }

    return finding


def main():
    parser = argparse.ArgumentParser(description="Transform enriched SBOM into Wiz SCA enrichment JSON")
    parser.add_argument("--input", default=INPUT_FILE, help="Enriched SBOM JSON from stage 1")
    parser.add_argument("--output", default=OUTPUT_FILE, help="Wiz enrichment JSON to write")
    args = parser.parse_args()

    cfg = get_config()

    print(f"Reading enriched SBOM: {args.input}")
    with open(args.input) as f:
        enriched = json.load(f)

    findings = enriched.get("findings", [])
    if not findings:
        print("ERROR: No findings in enriched SBOM. Run 01_enrich_sbom.py first.", file=sys.stderr)
        sys.exit(1)

    wiz_findings = [build_finding(f) for f in findings]

    analysis_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    envelope = {
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
                        "vulnerabilityFindings": wiz_findings,
                    }
                ],
            }
        ],
    }

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(envelope, f, indent=2)

    print(f"Transformed {len(wiz_findings)} findings into Wiz format")
    print(f"  Integration ID : {cfg['integration_id']}")
    print(f"  DataSource ID  : {cfg['datasource_id']}")
    print(f"  Asset           : {cfg['repo_name']}:{cfg['repo_branch']}")
    print(f"  Analysis date   : {analysis_date}")
    print(f"  Output          : {args.output}")


if __name__ == "__main__":
    main()
