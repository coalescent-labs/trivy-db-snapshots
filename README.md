# trivy-db-snapshots

Dated, frozen snapshots of the public [Aqua Security Trivy](https://trivy.dev) databases
(vulnerability DB + Java index DB), published as GitHub Releases so our release bundles can be
scanned against a **fixed, declared point-in-time CVE set**.

## Why this exists

Aqua does **not** keep dated snapshots of the Trivy DB: `ghcr.io/aquasecurity/trivy-db:2` is the
*schema* tag and is overwritten roughly every 6 hours, so there is no "DB as of 1 May" to pull.
To pin the CVE knowledge a shipped bundle was assessed against — and to keep that assessment
stable for the bundle's patches — we capture the DB ourselves at a known instant and archive it.

Each snapshot records **`UpdatedAt`** (the moment Aqua built that DB). That timestamp is the
authoritative *as-of* date we declare to customers:

> *"Bundle 6.0 (July 2026) resolves the CVEs present in the public Aqua Trivy database as of
> `<UpdatedAt>`."*

## Layout of a snapshot (one GitHub Release per snapshot, tag = `YYYY.MM`)

| Asset | Contents |
|-------|----------|
| `trivy-db-<tag>.tar.gz`       | vulnerability DB (`db/`)      |
| `trivy-java-db-<tag>.tar.gz`  | Java index DB (`java-db/`)    |
| `snapshot-manifest-<tag>.json`| `dbUpdatedAt`, `javaDbUpdatedAt`, `trivyVersion`, `dbSchema`, `capturedAt` |

`db` and `java-db` are separate assets so neither approaches GitHub's 2 GiB per-file limit.
Release assets do not count toward repo size and are not billed, so retention is cheap.

## How it is produced

- **`.github/workflows/snapshot.yml`** — runs `scripts/snapshot-trivy-db.sh` on the **1st of every
  month at 06:00 UTC**, and on manual dispatch. Dispatch it with an explicit `tag` (e.g. `2026.07`)
  to force *today's* DB into a specific month — used to seed the current bundle just before release.
- **`.github/workflows/cleanup.yml`** — monthly; deletes snapshots older than 5 years.

Both use the repo's default `GITHUB_TOKEN` (`contents: write`). No org secrets are required.

## How it is consumed

The fleet's `scripts/run-trivy.sh` selects the DB with `--db`:

```bash
./scripts/run-trivy.sh --db latest        # current online DB, auto-updated   (nightly)
./scripts/run-trivy.sh --db bundle         # freeze to this bundle's DB, derived from version-bundle.txt (release)
./scripts/run-trivy.sh --db 2026.07        # freeze to a specific snapshot     (patches / reproduce a past scan)
```

`--db bundle` reads `version-bundle.txt` (e.g. `6.0.2607`) and derives the snapshot tag from the
last four digits (`2607` → `2026.07`). Frozen scans run with `--skip-db-update --skip-java-db-update`
so the CVE set never drifts.

> **Schema note:** the DB `schema` (currently v2) is tied to the Trivy version. A frozen snapshot
> must be scanned with a Trivy that supports its schema — the manifest records `trivyVersion`, and
> `run-trivy.sh`'s Docker fallback pins that version automatically in frozen mode.

## Producing a snapshot locally

```bash
gh auth login                                   # needs write on this repo
./scripts/snapshot-trivy-db.sh --tag 2026.07    # downloads today's DB, publishes release 2026.07
./scripts/snapshot-trivy-db.sh --tag 2026.07 --dry-run   # build assets only, no release
```

## Visibility

This repository is **public**: it mirrors already-public Trivy data, so there is nothing to
protect, and public access means consumers fetch snapshots with a plain unauthenticated `curl`
(no tokens anywhere). Write access — creating/deleting releases — remains restricted to the
organization, as enforced by GitHub permissions.
