#!/usr/bin/env bash
set -euo pipefail

# Full pipeline: SBOM → enrich → transform → upload → verify
# Usage: ./run_pipeline.sh [path-to-sbom.json]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SBOM="${1:-$SCRIPT_DIR/examples/sbom-spdx-2.3-example.json}"

echo "============================================"
echo "  SBOM → Wiz Vulnerability Findings Pipeline"
echo "============================================"
echo ""
echo "SBOM input: $SBOM"
echo ""

echo "--- Stage 1: Enrich SBOM with OSV vulnerability data ---"
python3 "$SCRIPT_DIR/01_enrich_sbom.py" --sbom "$SBOM"
echo ""

echo "--- Stage 2: Transform to Wiz SCA enrichment format ---"
python3 "$SCRIPT_DIR/02_transform_to_wiz.py"
echo ""

echo "--- Stage 3: Upload to Wiz API ---"
python3 "$SCRIPT_DIR/03_upload_to_wiz.py"
echo ""

echo "============================================"
echo "  Pipeline complete."
echo "  Findings will appear in Wiz within ~10 min."
echo "  Run: python3 04_verify_findings.py"
echo "============================================"
