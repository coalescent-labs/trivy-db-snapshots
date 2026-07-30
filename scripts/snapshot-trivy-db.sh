#!/usr/bin/env bash
#
# Copyright (c) 2026 Coalescent Labs S.p.A. - All Rights Reserved.
#
# Unauthorized copying of this file, via any medium is strictly prohibited.
# Proprietary and confidential.
#

# Capture a point-in-time snapshot of the public Aqua Security Trivy databases
# (vulnerability DB + Java index DB) and publish it as a GitHub Release asset set.
#
# WHY THIS EXISTS
#   Aqua does NOT keep dated snapshots: ghcr.io/aquasecurity/trivy-db:2 is the *schema*
#   tag and is overwritten every ~6h, so there is no "DB as of 1 May" to pull. To pin the
#   CVE knowledge a release bundle was scanned against, we must capture the DB ourselves at
#   a known instant and archive it. Each snapshot records `UpdatedAt` (the moment Aqua built
#   the DB) -- that is the authoritative "as-of" date we declare to customers.
#
# WHAT IT PRODUCES  (one GitHub Release per snapshot, tag = YYYY.MM)
#   trivy-db-<tag>.tar.gz         the vulnerability DB      (cache-dir/db/*)
#   trivy-java-db-<tag>.tar.gz    the Java index DB         (cache-dir/java-db/*)
#   snapshot-manifest-<tag>.json  dbUpdatedAt / javaDbUpdatedAt / trivyVersion / dbSchema / ...
#   (db and java-db are separate assets so neither ever approaches the 2 GiB per-file cap)
#
# Trivy resolution: uses a local `trivy` binary if present, otherwise falls back to the
# official Docker image (so CI without a preinstalled Trivy still works).
#
# Usage: ./scripts/snapshot-trivy-db.sh --tag 2026.07 [OPTIONS]
#
# Options:
#   --tag YYYY.MM         Snapshot tag / release tag (required). Convention: release month.
#   --captured-at ISO     Capture timestamp for the manifest (default: `date -u` now).
#   --repo OWNER/REPO     Target repo for the GitHub Release (default: this repo).
#   --trivy-image IMG     Docker image to use when no local trivy (default: aquasec/trivy:latest).
#   --dry-run             Build the assets locally but do NOT create the GitHub Release.
#   -h, --help            Show this help.

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; RED='\033[0;31m'; NC='\033[0m'

TAG=""
CAPTURED_AT=""
REPO=""
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:latest}"
DRY_RUN=false

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag) TAG="$2"; shift 2 ;;
        --captured-at) CAPTURED_AT="$2"; shift 2 ;;
        --repo) REPO="$2"; shift 2 ;;
        --trivy-image) TRIVY_IMAGE="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        -h|--help) usage ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; usage ;;
    esac
done

[[ -n "$TAG" ]] || { echo -e "${RED}✗ --tag YYYY.MM is required${NC}"; exit 1; }
[[ "$TAG" =~ ^[0-9]{4}\.[0-9]{2}$ ]] || { echo -e "${RED}✗ --tag must be YYYY.MM (e.g. 2026.07)${NC}"; exit 1; }

# jq and tar are required; a release also needs gh (unless --dry-run)
command -v jq  >/dev/null 2>&1 || { echo -e "${RED}✗ 'jq' is required${NC}"; exit 1; }
command -v tar >/dev/null 2>&1 || { echo -e "${RED}✗ 'tar' is required${NC}"; exit 1; }
if [[ "$DRY_RUN" == false ]]; then
    command -v gh >/dev/null 2>&1 || { echo -e "${RED}✗ 'gh' (GitHub CLI) is required to publish the release (or use --dry-run)${NC}"; exit 1; }
fi

# Work in a clean, isolated cache dir so we archive exactly this download and nothing else.
WORK_DIR="$(mktemp -d)"
CACHE_DIR="$WORK_DIR/cache"
OUT_DIR="$WORK_DIR/out"
mkdir -p "$CACHE_DIR" "$OUT_DIR"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

# Resolve the Trivy runner: native binary, else the official Docker image.
if command -v trivy >/dev/null 2>&1 && trivy --version >/dev/null 2>&1; then
    TRIVY=(trivy --cache-dir "$CACHE_DIR")
    TRIVY_SOURCE="local: $(trivy --version | head -1)"
else
    command -v docker >/dev/null 2>&1 || { echo -e "${RED}✗ neither 'trivy' nor 'docker' available${NC}"; exit 1; }
    TRIVY=(docker run --rm -v "$CACHE_DIR":/cache "$TRIVY_IMAGE" --cache-dir /cache)
    TRIVY_SOURCE="docker: $TRIVY_IMAGE"
fi

echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Trivy DB snapshot  →  ${TAG}                 ${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"
echo "  Trivy       : $TRIVY_SOURCE"
echo "  Cache (temp): $CACHE_DIR"
echo ""

# 1) Download both databases into the isolated cache (no scan).
echo -e "${GREEN}▶ Downloading vulnerability DB...${NC}"
"${TRIVY[@]}" image --download-db-only
echo -e "${GREEN}▶ Downloading Java index DB...${NC}"
"${TRIVY[@]}" image --download-java-db-only

[[ -f "$CACHE_DIR/db/metadata.json"      ]] || { echo -e "${RED}✗ vuln DB metadata missing${NC}"; exit 1; }
[[ -f "$CACHE_DIR/java-db/metadata.json" ]] || { echo -e "${RED}✗ java DB metadata missing${NC}"; exit 1; }

# 2) Read the authoritative as-of timestamps and schema versions from the DB metadata.
DB_UPDATED_AT="$(jq -r '.UpdatedAt // .updatedAt // "unknown"'     "$CACHE_DIR/db/metadata.json")"
DB_SCHEMA="$(jq -r     '.Version   // .version   // "unknown"'     "$CACHE_DIR/db/metadata.json")"
JAVADB_UPDATED_AT="$(jq -r '.UpdatedAt // .updatedAt // "unknown"' "$CACHE_DIR/java-db/metadata.json")"
JAVADB_SCHEMA="$(jq -r '.Version // .version // "unknown"'         "$CACHE_DIR/java-db/metadata.json")"
TRIVY_VERSION="$("${TRIVY[@]}" --version | awk '/^Version:/{print $2; exit}')"
[[ -n "$CAPTURED_AT" ]] || CAPTURED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# 3) Manifest -- the machine-readable declaration that travels with the snapshot.
cat > "$OUT_DIR/snapshot-manifest-${TAG}.json" <<EOF
{
  "tag": "${TAG}",
  "dbUpdatedAt": "${DB_UPDATED_AT}",
  "dbSchema": ${DB_SCHEMA},
  "javaDbUpdatedAt": "${JAVADB_UPDATED_AT}",
  "javaDbSchema": ${JAVADB_SCHEMA},
  "trivyVersion": "${TRIVY_VERSION}",
  "capturedAt": "${CAPTURED_AT}",
  "source": {
    "db": "ghcr.io/aquasecurity/trivy-db:2",
    "javaDb": "ghcr.io/aquasecurity/trivy-java-db:1"
  }
}
EOF

# 4) Package db and java-db as SEPARATE tarballs (keeps each well under the 2 GiB asset cap).
#    Archive relative to the cache dir so the tree unpacks straight back into a Trivy cache.
echo -e "${GREEN}▶ Packaging assets...${NC}"
tar -C "$CACHE_DIR" -czf "$OUT_DIR/trivy-db-${TAG}.tar.gz"      db
tar -C "$CACHE_DIR" -czf "$OUT_DIR/trivy-java-db-${TAG}.tar.gz" java-db

warn_if_big() {
    local f="$1" bytes; bytes=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f")
    local gib=$(( 2 * 1024 * 1024 * 1024 ))
    # NB: use `if`, not `(( ... )) && echo`. Under `set -e` a false `(( ))` returns 1, which would
    # become this function's exit status and abort the whole script at the call site.
    if (( bytes > gib )); then
        echo -e "${YELLOW}⚠ $(basename "$f") is $((bytes/1024/1024)) MiB — near/over the 2 GiB asset cap${NC}"
    fi
}
for f in "$OUT_DIR"/*.tar.gz; do warn_if_big "$f"; done

echo ""
echo -e "${YELLOW}Snapshot ${TAG}:${NC}"
printf "  %-18s %s\n" "DB UpdatedAt:"      "$DB_UPDATED_AT   (schema v$DB_SCHEMA)"
printf "  %-18s %s\n" "Java DB UpdatedAt:" "$JAVADB_UPDATED_AT   (schema v$JAVADB_SCHEMA)"
printf "  %-18s %s\n" "Trivy version:"     "$TRIVY_VERSION"
printf "  %-18s %s\n" "Captured at:"       "$CAPTURED_AT"
ls -lh "$OUT_DIR" | awk 'NR>1{printf "  %-32s %s\n", $9, $5}'
echo ""

if [[ "$DRY_RUN" == true ]]; then
    echo -e "${YELLOW}⚠ --dry-run: assets left in ${OUT_DIR} (will be removed on exit); no release created${NC}"
    # Keep the artifacts for inspection by copying next to the repo before the trap cleans up.
    cp "$OUT_DIR"/* "./" 2>/dev/null || true
    echo -e "${GREEN}✓ Copied assets to $(pwd) for inspection${NC}"
    exit 0
fi

# 5) Publish the GitHub Release. The release notes ARE the human-readable declaration.
REPO_ARG=(); [[ -n "$REPO" ]] && REPO_ARG=(--repo "$REPO")
NOTES=$(cat <<EOF
Frozen snapshot of the public Aqua Security Trivy databases.

- **Public DB as-of (UpdatedAt): \`${DB_UPDATED_AT}\`** ← the date this snapshot certifies CVE knowledge to
- Java index DB UpdatedAt: \`${JAVADB_UPDATED_AT}\`
- DB schema: v${DB_SCHEMA} · Java DB schema: v${JAVADB_SCHEMA}
- Produced with Trivy \`${TRIVY_VERSION}\` (frozen scans must run with a Trivy that supports schema v${DB_SCHEMA})
- Captured at: \`${CAPTURED_AT}\`

Consumed by \`run-trivy.sh --db ${TAG}\` (or \`--db bundle\`, which derives this tag from \`version-bundle.txt\`).
EOF
)

echo -e "${GREEN}▶ Creating GitHub Release ${TAG}...${NC}"
if gh release view "$TAG" "${REPO_ARG[@]}" >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠ Release ${TAG} already exists — refreshing assets and notes${NC}"
    gh release upload "$TAG" "${REPO_ARG[@]}" --clobber "$OUT_DIR"/*
    # Keep the notes in sync with the just-clobbered assets/manifest (upload does not touch notes).
    gh release edit "$TAG" "${REPO_ARG[@]}" --title "Trivy DB snapshot ${TAG}" --notes "$NOTES"
else
    gh release create "$TAG" "${REPO_ARG[@]}" \
        --title "Trivy DB snapshot ${TAG}" \
        --notes "$NOTES" \
        "$OUT_DIR"/*
fi
echo -e "${GREEN}✓ Published snapshot ${TAG} (DB as-of ${DB_UPDATED_AT})${NC}"
