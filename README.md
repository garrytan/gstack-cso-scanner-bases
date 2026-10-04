# gstack CSO scanner bases

Attested base images for the six scanners that gstack's `/cso` runs in containment
(gitleaks, OSV-Scanner, Semgrep, zizmor, Trivy, Schemathesis), plus the BuildKit SBOM
generator gstack's scanner release workflow uses. gstack's
[`lib/cso/scanner-images/build-inputs.json`](https://github.com/garrytan/gstack/blob/main/lib/cso/scanner-images/build-inputs.json)
pins these images by digest, and its `cso-scanner-images.yml` workflow re-verifies every
signature below before building its own wrapper images on top.

## Why this repository exists

gstack's release workflow accepts a base image only when `gh attestation verify` proves
SLSA provenance and an SPDX 2.3 SBOM signed by a named GitHub workflow at a named commit.
None of the upstream scanner images publish GitHub artifact attestations, so this
repository re-publishes each pinned upstream digest, adds the reviewed offline assets,
and signs the result with its own workflow.

## What each image contains

| Scanner | Upstream (pinned in `inputs.json`) | Added here |
|---|---|---|
| gitleaks | `ghcr.io/gitleaks/gitleaks` | nothing |
| osv | `ghcr.io/google/osv-scanner` | complete OSV advisory exports for 12 ecosystems at `/opt/cso/scanner-data/osv` |
| semgrep | `docker.io/semgrep/semgrep` | security-category rules from `opengrep/opengrep-rules` at `/policy/catalog/semgrep` |
| zizmor | `ghcr.io/zizmorcore/zizmor` | nothing |
| trivy | `ghcr.io/aquasecurity/trivy` (cosign-verified) | vulnerability DB and misconfiguration checks bundle at `/opt/cso/scanner-data/trivy` |
| schemathesis | gstack's reviewed `python:3.13.4-slim-bookworm` digests | hash-locked Schemathesis wheels and an argv[0] shim |

Schemathesis also serves as the Python runtime for gstack's API harness, whose verifier
is a glibc binary, so it builds on Debian rather than the upstream Alpine image.

Semgrep's current registry rules forbid redistribution. The bundled rules come from the
frozen `opengrep-rules` fork (LGPL-2.1 with the Commons Clause), whose license file and a
modification notice ship inside the bundle.

## Publishing

Pushing a `bases-*` tag runs `.github/workflows/publish.yml`:

1. `scripts/verify-upstream.sh` re-resolves every upstream tag and refuses drift in the
   index digest, platform membership, architecture or revision label, and verifies
   Trivy's keyless signature against its release workflow.
2. One job acquires the assets once (`assets/acquire.sh`) and hashes them with gstack's
   own `hash-asset` algorithm, so both platforms carry byte-identical content.
3. Native amd64 and arm64 jobs build each base, smoke-test the scanner version and asset
   hash from the pushed digest, generate an SPDX SBOM with Syft, attest provenance and
   SBOM, and verify both exactly as gstack does.
4. The release attaches a `build-inputs.json` candidate (state `pending`), the asset
   manifests and all verification output.

Images are published to `ghcr.io/garrytan/gstack-cso-scanner-bases`, which must be a
public package so gstack's workflow and users can pull it anonymously.

## Refreshing advisory databases

Push a new `bases-*` tag. The release's `build-inputs.json` then goes through gstack's
normal human review before its state changes to `reviewed`.
