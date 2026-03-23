# Import External SBOM → Wiz Vulnerability Findings

Upload third-party SBOM data into Wiz as real, tracked vulnerability findings on a code repository branch. Fills gaps where Wiz's native scanner can't see all dependencies (multi-language monorepos, custom build systems, vendored code).

## What It Does

This pipeline takes an SPDX 2.3 SBOM, enriches it with vulnerability data from the free OSV.dev API, transforms the results into Wiz's SCA enrichment format, and uploads them via the Wiz WIN API. The findings show up in Wiz as real vulnerability entries — visible in UVM dashboards, triggering Issues per your rules, and tracked over time.

```
SPDX 2.3 SBOM  →  OSV.dev Vuln Lookup  →  Wiz SCA JSON  →  Wiz WIN API  →  Security Graph
```

### Proven Results

Tested on `ppresto/aws-wiz-c2c` branch `main`:
- **Before:** 96 vulnerability findings (Wiz native scan)
- **After upload:** 99 findings (3 new CVEs from external SBOM)
- All 3 appeared with `detection=LIBRARY`, `source=Custom Integration`
- Propagation time: ~10 minutes after successful upload

## Prerequisites

### 1. Python 3.10+

```bash
python3 --version
```

### 2. Wiz Service Account

Create or use a service account in your Wiz tenant with these scopes:

| Scope | Purpose |
|---|---|
| `create:external_data_ingestion` | Request upload slot and push findings |
| `read:system_activities` | Poll upload processing status |
| `read:vulnerabilities` | Verify findings appeared on the branch |

**How to add scopes:**
1. Go to Wiz → Settings → Service Accounts
2. Select your service account (or create a new one)
3. Under **API Scopes**, add the three scopes above
4. Save and note the Client ID and Client Secret

### 3. Target Repository Branch Asset ID

You need the Wiz Asset ID for the specific repository branch you're targeting.

**How to find it:**
1. Go to Wiz → Inventory → Code → Repositories
2. Click your repository
3. The asset ID is in the URL, or you can query via API:
   ```bash
   # Example: search for your repo
   curl -s -X POST "$WIZ_API/graphql" \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"query":"{ repositoryBranches(filterBy:{search:\"your-repo\"}, first:5) { nodes { id name } } }"}'
   ```

### 4. Wiz Integration ID

This pipeline uses the built-in enrichment integration ID: `55c176cc-d155-43a2-98ed-aa56873a1ca1`. It works with any service account that has the `create:external_data_ingestion` scope. No additional connector setup required.

## Setup

```bash
# Navigate to this directory
cd ~/Projects/wiz-Py/import-sbom-to-vulns-to-wiz

# Create a virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Configure environment
# Option A: Use the demo config (pre-filled for ppresto/aws-wiz-c2c)
cp .env.demo .env

# Option B: Start from blank template for your own repo
cp .env.example .env
# Edit .env with your values
```

### Environment Variables

| Variable | Description | Example |
|---|---|---|
| `WIZ_CLIENT_ID` | Service account client ID | `abc123...` |
| `WIZ_CLIENT_SECRET` | Service account secret | `xyz789...` |
| `WIZ_TOKEN_URL` | OAuth token endpoint | `https://auth.app.wiz.io/oauth/token` |
| `WIZ_INTEGRATION_ID` | Enrichment integration ID | `55c176cc-d155-43a2-98ed-aa56873a1ca1` |
| `REPO_ASSET_ID` | Wiz asset ID for the repo branch | `b2fbac40-63b8-...` |
| `REPO_NAME` | GitHub owner/repo | `ppresto/aws-wiz-c2c` |
| `REPO_BRANCH` | Branch name | `main` |
| `REPO_URL` | Full GitHub URL | `https://github.com/ppresto/aws-wiz-c2c` |
| `VCS_TYPE` | Version control system | `GitHub` |
| `DATASOURCE_ID` | Stable ID for finding replacement | `sbom-import-ppresto-aws-wiz-c2c-main` |

**Tip:** If you already have `~/wizAPI.sh` that exports `WIZ_CLIENT_ID` and `WIZ_CLIENT_SECRET`, source it first and the scripts will pick up those values automatically.

## Usage

### Run Full Pipeline

```bash
# Activate venv + source your Wiz creds
source .venv/bin/activate
source ~/wizAPI.sh

# Run all stages with the included example SBOM
./run_pipeline.sh

# Or point to your own SBOM
./run_pipeline.sh /path/to/your-sbom.spdx.json
```

### Run Individual Stages

Each stage is a standalone script. Run them one at a time for debugging:

```bash
# Stage 1: Parse SBOM + lookup vulns via OSV.dev
python3 01_enrich_sbom.py --sbom examples/sbom-spdx-2.3-example.json

# Stage 2: Transform into Wiz SCA enrichment JSON
python3 02_transform_to_wiz.py

# Stage 3: Upload to Wiz API
python3 03_upload_to_wiz.py

# Stage 4: Verify findings appeared (wait ~10 min after upload)
python3 04_verify_findings.py

# Stage 5: Delete findings (demo reset)
python3 05_delete_findings.py
```

### Demo Flow

To run this as a repeatable demo:

```bash
# 1. Show the branch has N vulns (before)
python3 04_verify_findings.py

# 2. Run the full pipeline
./run_pipeline.sh

# 3. Wait ~10 minutes, then verify new findings
python3 04_verify_findings.py

# 4. Clean up (reset for next demo)
python3 05_delete_findings.py

# 5. Wait ~10 minutes, verify findings are gone
python3 04_verify_findings.py
```

## File Structure

```
import-sbom-to-vulns-to-wiz/
├── README.md                           ← This file
├── requirements.txt                    ← Python dependencies
├── .env.example                        ← Template for your config
├── .env.demo                           ← Pre-filled demo values (no secrets)
├── .gitignore
├── run_pipeline.sh                     ← Run all stages end-to-end
├── 01_enrich_sbom.py                   ← Stage 1: SBOM → OSV lookup
├── 02_transform_to_wiz.py             ← Stage 2: Enriched → Wiz JSON
├── 03_upload_to_wiz.py                 ← Stage 3: Upload to Wiz API
├── 04_verify_findings.py               ← Stage 4: Confirm findings on branch
├── 05_delete_findings.py               ← Stage 5: Remove findings (demo reset)
├── lib/
│   └── wiz_client.py                   ← Shared auth + API helper
├── examples/
│   └── sbom-spdx-2.3-example.json     ← Sample SBOM (3 known-vuln packages)
└── output/                             ← Generated files (git-ignored)
    ├── enriched-sbom.json              ← Stage 1 output
    └── wiz-enrichment.json             ← Stage 2 output
```

## How It Works (Technical Detail)

### Stage 1: Enrich SBOM

- Parses SPDX 2.3 JSON, extracts packages via Package URL (purl)
- Maps purl ecosystem to OSV ecosystem (Maven, Go, Debian, npm, etc.)
- Queries the free [OSV.dev API](https://osv.dev/) for each package+version
- Outputs a flat list of findings with CVE, severity, fixed version, and package metadata

### Stage 2: Transform to Wiz Format

- Reads the enriched output from Stage 1
- Wraps each finding in Wiz's SCA Application Vulnerability Findings schema
- Sets the `integrationId`, `dataSource.id`, and `repositoryBranch` asset mapping
- The `dataSource.id` is critical: keeping it consistent across runs means Wiz **replaces** old findings instead of duplicating them

### Stage 3: Upload to Wiz

- Authenticates via OAuth (client credentials flow)
- Calls `requestSecurityScanUpload` to get a pre-signed S3 URL
- PUTs the enrichment JSON to S3
- Polls `systemActivity` until status is `SUCCESS` or `FAILURE`

### Stage 5: Delete (Demo Reset)

- Uploads an enrichment file with the **same** `dataSource.id` but an **empty** `vulnerabilityFindings` array
- Wiz replaces the previous findings with nothing, removing them from the branch

## Limitations

- **Not a replacement for Wiz's native scanner.** Enrichment findings coexist alongside native scan results. If both detect the same CVE, you'll see duplicates (different `dataSourceName`).
- **SBOM quality matters.** If your SBOM has wrong versions or missing packages, the vuln lookup will miss real issues.
- **Propagation delay.** Findings take ~10 minutes to appear after upload. The `systemActivity` status confirms ingestion succeeded even before findings are visible.
- **OSV coverage varies.** OSV has excellent coverage for Maven, npm, PyPI, Go, and Rust. Coverage for OS packages (deb, rpm) is more limited.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `access denied` on upload | Missing SA scope | Add `create:external_data_ingestion` to your service account |
| `systemActivity` returns `FAILURE` | Wrong `integrationId` or bad JSON schema | Use `55c176cc-d155-43a2-98ed-aa56873a1ca1` and validate JSON against the SCA schema |
| Findings don't appear after 30 min | Asset ID mismatch | Verify `REPO_ASSET_ID` matches the exact branch in Wiz Inventory |
| OSV returns 0 vulns for a package | Package not in OSV database | Try a different ecosystem mapping, or use grype/trivy as an alternative scanner |
| `WIZ_CLIENT_ID is not set` | .env not configured | Copy `.env.example` → `.env` and fill in values, or `source ~/wizAPI.sh` first |
