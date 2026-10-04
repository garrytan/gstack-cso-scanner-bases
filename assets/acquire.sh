#!/usr/bin/env bash
# Acquire the offline scanner assets into OUT/{semgrep,osv,trivy}.
# Inputs come only from inputs.json (pinned rules commit, trivy image digest, OSV ecosystems).
# Usage: assets/acquire.sh OUT RULES_CHECKOUT PYTHON
set -euo pipefail
out="$1" rules="$2" python="$3"
here="$(cd "$(dirname "$0")" && pwd)" inputs="$here/../inputs.json"
acquired_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
test ! -e "$out"; mkdir -p "$out"

# Semgrep: curated security subset of the pinned opengrep-rules commit (LGPL-2.1 + Commons Clause).
test "$(git -C "$rules" rev-parse HEAD)" = "$(jq -er '.assets.semgrep.commit' "$inputs")"
"$python" "$here/semgrep/curate.py" "$rules" "$out/semgrep" "$here/semgrep/exclude.txt"
cp "$rules/LICENSE" "$out/semgrep/LICENSE"
jq -n --arg repo "$(jq -er '.assets.semgrep.repository' "$inputs")" --arg commit "$(jq -er '.assets.semgrep.commit' "$inputs")" \
  --arg sha "$(sha256sum "$out/semgrep/rules.yml" | cut -d' ' -f1)" \
  '{notice:"Modified: security-category subset of the upstream rules; rule ids are prefixed with their source directory. Upstream license (LGPL-2.1 with Commons Clause) is in LICENSE.",source:$repo,commit:$commit,rulesSha256:$sha}' > "$out/semgrep/NOTICE.json"

# OSV: complete per-ecosystem advisory exports, integrity-checked against the bucket's MD5.
base="$(jq -er '.assets.osv.bucket' "$inputs")"
mkdir -p "$out/osv/osv-scalibr"
manifest='{}'
while IFS= read -r eco; do
  dir="$out/osv/osv-scalibr/$eco"; mkdir -p "$dir"
  url="$base/$(jq -rn --arg e "$eco" '$e|@uri')/all.zip"
  curl -fsSL --retry 3 -D "$dir.headers" -o "$dir/all.zip" "$url"
  md5_b64="$(tr -d '\r' < "$dir.headers" | sed -n 's/^x-goog-hash: md5=//Ip' | head -1)"
  modified="$(tr -d '\r' < "$dir.headers" | sed -n 's/^last-modified: //Ip' | head -1)"
  test -n "$md5_b64"
  test "$(openssl dgst -md5 -binary "$dir/all.zip" | base64)" = "$md5_b64"
  rm "$dir.headers"
  manifest="$(jq --arg e "$eco" --arg m "$modified" --arg s "$(sha256sum "$dir/all.zip" | cut -d' ' -f1)" --argjson b "$(stat -c %s "$dir/all.zip")" '.[$e]={lastModified:$m,sha256:$s,bytes:$b}' <<<"$manifest")"
done < <(jq -er '.assets.osv.ecosystems[]' "$inputs")
jq -n --arg at "$acquired_at" --arg src "$base" --argjson e "$manifest" '{source:$src,acquiredAt:$at,ecosystems:$e}' > "$out/osv/manifest.json"

# Trivy: vulnerability DB downloaded by the pinned Trivy image itself.
trivy_image="$(jq -er '.scanners.trivy.upstream.platforms["linux/amd64"]' "$inputs")"
mkdir -p "$out/trivy"; chmod 0777 "$out/trivy"
docker run --rm --network bridge --user "$(id -u):$(id -g)" -v "$out/trivy:/cache" "$trivy_image" \
  --cache-dir /cache --quiet image --download-db-only --db-repository "$(jq -er '.assets.trivy.dbRepository' "$inputs")"
# Misconfiguration checks bundle, fetched by the same Trivy through a throwaway config scan.
mkdir -p "$out/trivy-empty"
docker run --rm --network bridge --user "$(id -u):$(id -g)" -v "$out/trivy:/cache" -v "$out/trivy-empty:/empty:ro" "$trivy_image" \
  --cache-dir /cache --quiet config --checks-bundle-repository "$(jq -er '.assets.trivy.checksRepository' "$inputs")" /empty >/dev/null
rmdir "$out/trivy-empty"
test -s "$out/trivy/policy/metadata.json"; test -d "$out/trivy/policy/content"
rm -rf "$out/trivy/fanal"
jq -e '.Version == 2 and (.UpdatedAt|type=="string")' "$out/trivy/db/metadata.json" >/dev/null
jq -n --arg at "$acquired_at" --arg repo "$(jq -er '.assets.trivy.dbRepository' "$inputs")" --slurpfile meta "$out/trivy/db/metadata.json" \
  --arg sha "$(sha256sum "$out/trivy/db/trivy.db" | cut -d' ' -f1)" --slurpfile checks "$out/trivy/policy/metadata.json" '{source:$repo,acquiredAt:$at,dbUpdatedAt:$meta[0].UpdatedAt,trivyDbSha256:$sha,checksBundle:$checks[0]}' > "$out/trivy/manifest.json"

chmod -R u=rwX,go=rX "$out"
echo "$acquired_at" > "$out/acquired-at"
