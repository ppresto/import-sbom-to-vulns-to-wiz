#!/usr/bin/env python3
"""
Stage 1: Parse an SPDX 2.3 SBOM and enrich each package with vulnerability
data from the OSV.dev API (free, no auth required).

Input:  SPDX 2.3 JSON file  (default: examples/sbom-spdx-2.3-example.json)
Output: output/enriched-sbom.json
"""

import argparse
import json
import os
import re
import sys
from urllib.parse import unquote

import requests

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SBOM = os.path.join(SCRIPT_DIR, "examples", "sbom-spdx-2.3-example.json")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "output")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "enriched-sbom.json")

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"

PURL_ECOSYSTEM_MAP = {
    "maven": "Maven",
    "npm": "npm",
    "pypi": "PyPI",
    "golang": "Go",
    "cargo": "crates.io",
    "nuget": "NuGet",
    "gem": "RubyGems",
    "deb": "Debian",
    "apk": "Alpine",
    "rpm": "Red Hat",
}

PURL_LANG_MAP = {
    "maven": "Java",
    "npm": "JavaScript",
    "pypi": "Python",
    "golang": "Golang",
    "cargo": "Rust",
    "nuget": "CSharp",
    "gem": "Ruby",
    "deb": "Other",
    "apk": "Other",
    "rpm": "Other",
}


def parse_purl(purl: str) -> dict:
    """Extract ecosystem, namespace/name, and version from a Package URL."""
    match = re.match(r"pkg:(\w+)/(.+?)@(.+?)(?:\?.*)?$", purl)
    if not match:
        return {}
    purl_type = match.group(1)
    raw_name = unquote(match.group(2))
    version = unquote(match.group(3))

    osv_ecosystem = PURL_ECOSYSTEM_MAP.get(purl_type, purl_type)
    language = PURL_LANG_MAP.get(purl_type, "Other")

    if purl_type == "maven":
        osv_name = raw_name.replace("/", ":")
    elif purl_type == "deb":
        osv_name = raw_name.split("/", 1)[-1]
    else:
        osv_name = raw_name

    return {
        "purl": purl,
        "purl_type": purl_type,
        "ecosystem": osv_ecosystem,
        "name": osv_name,
        "version": version,
        "language": language,
    }


def extract_file_path(pkg: dict) -> str:
    """Best-effort extraction of source file path from SPDX comment field."""
    comment = pkg.get("comment", "")
    match = re.search(r"Source file:\s*(\S+)", comment)
    if match:
        return match.group(1)
    lang = ""
    for ref in pkg.get("externalRefs", []):
        purl = ref.get("referenceLocator", "")
        if purl.startswith("pkg:"):
            parsed = parse_purl(purl)
            lang = parsed.get("purl_type", "")
    defaults = {
        "maven": "pom.xml",
        "npm": "package.json",
        "golang": "go.mod",
        "pypi": "requirements.txt",
        "cargo": "Cargo.toml",
        "deb": "Dockerfile",
    }
    return defaults.get(lang, "unknown")


def query_osv(ecosystem: str, name: str, version: str) -> list[dict]:
    """Query OSV.dev for vulnerabilities affecting a specific package version."""
    payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    try:
        resp = requests.post(OSV_QUERY_URL, json=payload, timeout=30)
        resp.raise_for_status()
        return resp.json().get("vulns", [])
    except requests.RequestException as e:
        print(f"  WARNING: OSV query failed for {ecosystem}/{name}@{version}: {e}", file=sys.stderr)
        return []


def _cvss_vector_to_severity(vector: str) -> str:
    """Estimate severity from a CVSS 3.x vector string like CVSS:3.1/AV:N/AC:L/..."""
    metrics = {}
    for segment in vector.split("/"):
        if ":" in segment:
            k, v = segment.split(":", 1)
            metrics[k] = v

    av = metrics.get("AV", "N")
    ac = metrics.get("AC", "L")
    pr = metrics.get("PR", "N")
    s = metrics.get("S", "U")
    c = metrics.get("C", "N")
    i = metrics.get("I", "N")
    a = metrics.get("A", "N")

    high_impacts = sum(1 for x in [c, i, a] if x == "H")

    if av == "N" and s == "C" and high_impacts >= 2:
        return "Critical"
    if av == "N" and ac == "L" and pr == "N" and s == "C" and high_impacts >= 1:
        return "Critical"
    if av == "N" and high_impacts >= 2:
        return "High"
    if av == "N" and ac == "L" and high_impacts >= 1:
        return "High"
    if av == "N":
        return "Medium"
    if high_impacts >= 1:
        return "Medium"
    return "Low"


def osv_severity(vuln: dict) -> str:
    """Extract severity from OSV vuln data (CVSS vector, database_specific, or heuristic)."""
    db_sev = vuln.get("database_specific", {}).get("severity", "")
    if isinstance(db_sev, str) and db_sev:
        norm = db_sev.strip().upper()
        mapping = {"CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Medium", "MEDIUM": "Medium", "LOW": "Low"}
        if norm in mapping:
            return mapping[norm]

    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        if "CVSS" in sev.get("type", "") and "/" in score_str:
            return _cvss_vector_to_severity(score_str)

    for affected in vuln.get("affected", []):
        eco_sev = affected.get("database_specific", {}).get("severity", "")
        if isinstance(eco_sev, str) and eco_sev:
            norm = eco_sev.strip().upper()
            mapping = {"CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Medium", "MEDIUM": "Medium", "LOW": "Low"}
            if norm in mapping:
                return mapping[norm]

    return "High"


def extract_fixed_version(vuln: dict, pkg_name: str) -> str:
    """Find the earliest fixed version from OSV affected ranges."""
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name") != pkg_name:
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return ""


def primary_cve(vuln: dict) -> str:
    """Return the first CVE alias, or the OSV ID if none."""
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return vuln.get("id", "UNKNOWN")


def enrich_package(pkg_info: dict, file_path: str) -> list[dict]:
    """Look up vulns for one package and return enriched finding dicts."""
    vulns = query_osv(pkg_info["ecosystem"], pkg_info["name"], pkg_info["version"])
    findings = []
    seen_cves = set()

    for vuln in vulns:
        cve = primary_cve(vuln)
        if cve in seen_cves:
            continue
        seen_cves.add(cve)

        severity = osv_severity(vuln)
        fixed = extract_fixed_version(vuln, pkg_info["name"])
        description = (vuln.get("summary") or vuln.get("details") or "")[:500]

        findings.append({
            "cve": cve,
            "osv_id": vuln.get("id", ""),
            "description": description,
            "severity": severity,
            "fixed_version": fixed,
            "link": f"https://nvd.nist.gov/vuln/detail/{cve}" if cve.startswith("CVE-") else vuln.get("references", [{}])[0].get("url", ""),
            "package_name": pkg_info["name"],
            "package_version": pkg_info["version"],
            "ecosystem": pkg_info["ecosystem"],
            "language": pkg_info["language"],
            "file_path": file_path,
        })

    return findings


def main():
    parser = argparse.ArgumentParser(description="Enrich an SPDX 2.3 SBOM with vulnerability data from OSV.dev")
    parser.add_argument("--sbom", default=DEFAULT_SBOM, help="Path to SPDX 2.3 JSON file")
    parser.add_argument("--output", default=OUTPUT_FILE, help="Path to write enriched JSON")
    args = parser.parse_args()

    print(f"Reading SBOM: {args.sbom}")
    with open(args.sbom) as f:
        sbom = json.load(f)

    if sbom.get("spdxVersion") != "SPDX-2.3":
        print(f"WARNING: Expected SPDX-2.3, got {sbom.get('spdxVersion')}", file=sys.stderr)

    packages = sbom.get("packages", [])
    print(f"Found {len(packages)} packages in SBOM\n")

    all_findings = []
    for pkg in packages:
        purl = None
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref["referenceLocator"]
                break

        if not purl:
            print(f"  SKIP: {pkg.get('name', '?')} — no purl found")
            continue

        pkg_info = parse_purl(purl)
        if not pkg_info:
            print(f"  SKIP: {purl} — could not parse")
            continue

        file_path = extract_file_path(pkg)
        print(f"  Querying OSV for {pkg_info['ecosystem']}/{pkg_info['name']}@{pkg_info['version']}...")
        findings = enrich_package(pkg_info, file_path)
        print(f"    → {len(findings)} vulnerabilities found")
        all_findings.extend(findings)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    result = {
        "sbom_source": args.sbom,
        "enrichment_source": "OSV.dev",
        "total_packages": len(packages),
        "total_findings": len(all_findings),
        "findings": all_findings,
    }
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\nWrote {len(all_findings)} enriched findings → {args.output}")


if __name__ == "__main__":
    main()
