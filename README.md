# Import an SBOM into Wiz as vulnerability findings

**In plain terms:** You provide a standard **SBOM file** (a list of software components). This tool looks up known vulnerabilities for those components, then **sends them into Wiz** so they appear like normal vulnerability findings on a **specific Git branch**.

**Who this is for:** Security or platform admins who can run a few terminal commands and edit a small config file. You do **not** need to write code.

---

## Quick start (first time)

Do these **in order** from your computer’s terminal.

| Step | What to do |
|------|------------|
| 1 | **Install [uv](https://docs.astral.sh/uv/getting-started/installation/)** (one-time). Check: `uv --version` |
| 2 | **Install Python 3.10+** if you don’t have it. Check: `python3 --version` |
| 3 | Open a terminal and **go to this project folder** (the folder that contains `README.md` and `run_pipeline.sh`). Example: `cd ~/path/to/import-sbom-to-vulns-to-wiz` |
| 4 | Run **`uv sync`** — this creates a local `.venv` folder and installs what the scripts need |
| 5 | **Create your config:** `cp .env.example .env` then open `.env` in a text editor and fill in at least **`REPO_ASSET_ID`**, **`REPO_NAME`**, **`REPO_BRANCH`**, **`REPO_URL`**, and **`DATASOURCE_ID`**. For Wiz login, either put **`WIZ_CLIENT_ID`** and **`WIZ_CLIENT_SECRET`** in `.env`, or use a script that exports them (e.g. `source ~/wizAPI.sh`) before each run |
| 6 | **Run the pipeline:** `source ~/wizAPI.sh` (if you use that for credentials), then **`./run_pipeline.sh`** |

**First time only:** if the script is “not executable”, run: `chmod +x run_pipeline.sh`

**After a successful upload:** wait **about 10–30 minutes**, then in Wiz open **Vulnerability findings** for your repo branch and filter by **Data source = Custom Integration** (wording may vary slightly in the UI).

---

## Where the new findings show up in Wiz

- They appear as **vulnerability findings** on the **repository branch** you set in `.env` (`REPO_ASSET_ID` / `REPO_NAME` / `REPO_BRANCH`).
- They are labeled with **Has External Source = True** like **Custom Integration** (not the same as Wiz’s built-in code scanner).
- **Wiz’s own scanner can still report other findings** on the same branch. Those are separate and are **not** removed when you “delete” SBOM findings (see below).

---

## Words you might see

| Term | Meaning |
|------|---------|
| **SBOM** | Software Bill of Materials — a file listing components (often SPDX JSON). |
| **uv** | A small tool that installs the Python libraries this project uses (`uv sync`). |
| **Service account** | A Wiz API user (Client ID + Secret) used by the scripts instead of your login. |
| **Branch asset ID** | A unique ID in Wiz for one **Git branch** of one repo. This is **`REPO_ASSET_ID`** in `.env`. It is **not** always the same as the “repository” ID in some saved URLs. |
| **DATASOURCE_ID** | A name **you choose** and **reuse** for this repo+branch so new uploads **replace** the previous SBOM import instead of stacking duplicates. |

---

## Prerequisites (checklist)

- [ ] **Python 3.10 or newer**
- [ ] **uv** installed ([installation](https://docs.astral.sh/uv/getting-started/installation/))
- [ ] A **Wiz service account** with these **API scopes**:  
  `create:external_data_ingestion`, `read:system_activities`, `read:vulnerabilities`  
  (Wiz → **Settings** → **Service Accounts** → your account → **API Scopes**)
- [ ] The **Wiz asset ID for the target Git branch** (see `.env.example` comments)

**Integration ID:** The scripts use the standard enrichment integration ID **`55c176cc-d155-43a2-98ed-aa56873a1ca1`**. Leave it as in `.env.example` unless Wiz documentation tells you otherwise.

---

## Configure `.env`

1. Copy the template: **`cp .env.example .env`**
2. Edit **`.env`** (never commit real secrets; `.env` is git-ignored).

**Minimum you must set:**

- **`REPO_ASSET_ID`** — branch asset ID from Wiz Inventory (see comments in `.env.example`)
- **`REPO_NAME`**, **`REPO_BRANCH`**, **`REPO_URL`**, **`VCS_TYPE`**
- **`DATASOURCE_ID`** — pick a stable string per repo+branch (e.g. `sbom-import-myorg-myrepo-main`)

**Wiz login (pick one):**

- Put **`WIZ_CLIENT_ID`** and **`WIZ_CLIENT_SECRET`** in `.env`, **or**
- Run **`source ~/wizAPI.sh`** (or similar) in the same terminal **before** each script so those variables exist in the environment.

**Optional:** You can keep a second local file named **`.env.demo`** (git-ignored) with non-secret repo settings and merge ideas from it into `.env`. New clones only get **`.env.example`** — always copy that to **`.env`** first.

---

## Run the full pipeline (upload SBOM → Wiz)

From **this project folder**:

```bash
uv sync                    # after clone or when dependencies change
source ~/wizAPI.sh         # if you use this for WIZ_CLIENT_ID / SECRET
./run_pipeline.sh          # uses the example SBOM under examples/
```

**Use your own SBOM file:**

```bash
./run_pipeline.sh /path/to/your-file.spdx.json
```

The script runs stages **1 → 2 → 3** (enrich → convert → upload). It does **not** run verify or delete.

---

## Run one step at a time (optional)

**Easiest:** use **`uv run python`** so you don’t have to “activate” the virtual environment:

```bash
cd /path/to/import-sbom-to-vulns-to-wiz
uv sync
source ~/wizAPI.sh

uv run python 01_enrich_sbom.py --sbom examples/sbom-spdx-2.3-example.json
uv run python 02_transform_to_wiz.py
uv run python 03_upload_to_wiz.py
uv run python 04_verify_findings.py
uv run python 05_delete_findings.py
```

**Alternative:** after `uv sync`, run **`source .venv/bin/activate`**, then use **`python`** instead of **`uv run python`**.

| Script | What it does |
|--------|----------------|
| `01_enrich_sbom.py` | Reads SPDX SBOM, asks OSV.dev for CVEs, writes `output/enriched-sbom.json` |
| `02_transform_to_wiz.py` | Builds `output/wiz-enrichment.json` for Wiz |
| `03_upload_to_wiz.py` | Sends the JSON to Wiz; wait for **SUCCESS** in the output |
| `04_verify_findings.py` | Lists findings on the branch (helps confirm upload after ~10–30 min) |
| `05_delete_findings.py` | **Removes only** findings from **this** SBOM import (same `DATASOURCE_ID`), not all Wiz scanner findings. **Important:** after **SUCCESS**, removals often take **much longer** than new uploads to show in the **Wiz API and UI** — **30+ minutes is common**, and **an hour or more** happens; keep re-checking **Custom Integration** or **`04_verify_findings.py`**. |

---

## Remove the SBOM-import findings (Stage 5: delete / demo reset)

1. `uv sync` and `source ~/wizAPI.sh` (same as upload)
2. **`uv run python 05_delete_findings.py`**
3. When the script shows **Status: SUCCESS**, ingestion is accepted — but **cleared findings can take a long time** to disappear from the **vulnerability API and UI**, often **longer than after an upload**. **30+ minutes is common**; **an hour or more** is possible. Keep re-running **`04_verify_findings.py`** or refreshing the UI with **Custom Integration** filtered.

**Note:** You may see a short **“Resource not found”** message while the script waits for Wiz to show the job status — that is common and not necessarily a failure if the final status is **SUCCESS**.

---

## Saved Wiz URLs vs your `.env`

Saved **Vulnerability findings** links sometimes filter by a **repository** ID. Your config uses **`REPO_ASSET_ID`**, which is usually the **branch** ID. Those IDs are **often different**.

**Tip:** In Wiz, filter findings by **Custom Integration** (or equivalent) and the correct **branch** so you’re looking at the same data the scripts use.

---

## Troubleshooting

| What you see | What it usually means | What to try |
|--------------|------------------------|-------------|
| `WIZ_CLIENT_ID is not set` | No credentials in environment | Add them to `.env` or run `source ~/wizAPI.sh` before the script |
| `ModuleNotFoundError` for `dotenv` or `requests` | Dependencies missing | From **this folder**, run **`uv sync`** |
| `access denied` on upload | Service account missing scope | Add **`create:external_data_ingestion`** |
| Upload shows **FAILURE** | Bad integration ID or bad JSON | Keep **`WIZ_INTEGRATION_ID`** as in `.env.example`; check Wiz docs / support |
| Findings never show (30+ min) | Wrong branch asset | Confirm **`REPO_ASSET_ID`** is the **branch** in Inventory, not another resource |
| Delete **SUCCESS** but vulns still visible | Normal delay (often **longer than upload**, sometimes **1+ hours**) or wrong filter | Filter **Custom Integration**; wait **30+ minutes** or more; confirm **`REPO_ASSET_ID`**; re-run **`04_verify_findings.py`** |
| Many vulns left after delete | Not from this tool | Wiz’s own scanner findings stay; only **Custom Integration** rows from this **`DATASOURCE_ID`** are cleared |

---

## Limitations

- This **adds** findings; it does **not** turn off Wiz’s normal scanning.
- The same CVE can appear **twice** if both Wiz and this import report it (different sources).
- OSV.dev coverage depends on language/ecosystem; some packages may return no CVEs.
- There is **delay** between **SUCCESS** in the script and what you see in the UI — especially after a **delete**, which can lag **much longer** than after an upload (sometimes **an hour or more**).

---

## How it works (technical summary)

1. **Enrich:** SPDX 2.3 → package list → [OSV.dev](https://osv.dev/) lookup → `output/enriched-sbom.json`
2. **Transform:** Builds Wiz SCA enrichment JSON with `integrationId`, stable `dataSources[].id`, and branch mapping → `output/wiz-enrichment.json`
3. **Upload:** OAuth → presigned upload → Wiz processes the file → **`systemActivity`** reports **SUCCESS** or **FAILURE**
4. **Delete:** Same envelope with an **empty** list of findings for the same **`DATASOURCE_ID`** so Wiz **replaces** the previous import. **`systemActivity` SUCCESS** does not mean the UI/API reflects removals immediately — **propagation for deletes is often slower than for uploads** (think **30+ minutes**, sometimes **much longer**).

---

## Files in this folder

```
import-sbom-to-vulns-to-wiz/
├── README.md                 ← This guide
├── pyproject.toml            ← Dependency list for uv
├── uv.lock                   ← Locked versions (commit with the repo)
├── .env.example              ← Copy to .env and edit
├── .gitignore
├── run_pipeline.sh           ← Stages 1–3 in one go (uses uv)
├── 01_enrich_sbom.py … 05_delete_findings.py
├── lib/wiz_client.py         ← Shared Wiz API helper
├── examples/
│   └── sbom-spdx-2.3-example.json
└── output/                   ← Created when you run scripts (git-ignored)
    ├── enriched-sbom.json
    └── wiz-enrichment.json
```

---

## Example results (reference)

On a sample repo, a run may add a number of **Custom Integration** findings (library/detection details depend on the SBOM). Counts vary by SBOM and OSV data. Always confirm in the Wiz UI with the **Custom Integration** filter after propagation.
