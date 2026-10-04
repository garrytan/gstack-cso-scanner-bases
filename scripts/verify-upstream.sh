#!/usr/bin/env bash
# Re-resolve every pinned upstream image and refuse drift: the reviewed tag must
# still name the pinned index, each platform digest must be a member of that
# index with the declared architecture, the OCI revision label must match the
# pin, and Trivy's keyless signature must verify against its release workflow.
set -euo pipefail
inputs="${1:-inputs.json}"
cosign="$(jq -er '.tools.cosign' "$inputs")"
check_image() {
  local source="$1" index="$2" platforms="$3" revision="$4"
  local raw; raw="$(docker buildx imagetools inspect --raw "$source")"
  local tag_digest="sha256:$(printf '%s' "$raw" | sha256sum | cut -d' ' -f1)"
  test "$tag_digest" = "${index##*@}" || { echo "DRIFT: $source now resolves to $tag_digest, pinned ${index##*@}" >&2; exit 1; }
  for platform in linux/amd64 linux/arm64; do
    local pinned; pinned="$(jq -er --arg p "$platform" '.[$p]' <<<"$platforms")"
    local os="${platform%/*}" arch="${platform#*/}"
    printf '%s' "$raw" | jq -e --arg d "${pinned##*@}" --arg os "$os" --arg arch "$arch" \
      '[.manifests[] | select(.digest == $d and .platform.os == $os and .platform.architecture == $arch)] | length == 1' >/dev/null \
      || { echo "MISSING: $pinned is not the $platform member of $index" >&2; exit 1; }
    local config; config="$(docker buildx imagetools inspect --format '{{json .Image}}' "$pinned")"
    jq -e --arg arch "$arch" '.architecture == $arch' <<<"$config" >/dev/null || { echo "ARCH: $pinned" >&2; exit 1; }
    if test -n "$revision"; then
      jq -e --arg r "$revision" '.config.Labels["org.opencontainers.image.revision"] == $r' <<<"$config" >/dev/null \
        || { echo "REVISION: $pinned label differs from $revision" >&2; exit 1; }
    fi
  done
  echo "verified $source -> ${index##*@}"
}
for scanner in $(jq -er '.scanners | keys[]' "$inputs"); do
  up="$(jq -c --arg s "$scanner" '.scanners[$s].upstream' "$inputs")"
  revision="$(jq -r 'if .source | startswith("docker.io/library/python") then "" else .revisionLabel end' <<<"$up")"
  check_image "$(jq -er .source <<<"$up")" "$(jq -er .index <<<"$up")" "$(jq -c .platforms <<<"$up")" "$revision"
  identity="$(jq -r '.cosignIdentity // empty' <<<"$up")"
  if test -n "$identity"; then
    docker run --rm "$cosign" verify --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      --certificate-identity "$identity" "$(jq -er .index <<<"$up")" >/dev/null
    echo "verified cosign signature for $(jq -er .index <<<"$up") by $identity"
  fi
done
gen="$(jq -c '.sbomGenerator.upstream' "$inputs")"
raw="$(docker buildx imagetools inspect --raw "$(jq -er .source <<<"$gen")")"
test "sha256:$(printf '%s' "$raw" | sha256sum | cut -d' ' -f1)" = "$(jq -er '.index | sub(".*@"; "")' <<<"$gen")"
echo "verified $(jq -er .source <<<"$gen")"
