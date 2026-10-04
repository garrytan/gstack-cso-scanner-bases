# A reviewed upstream scanner image plus one reviewed offline asset (Semgrep rules
# or an advisory database). The asset is copied verbatim; its tree hash is
# recomputed before and after the build.
ARG UPSTREAM_IMAGE
FROM ${UPSTREAM_IMAGE}
ARG UPSTREAM_IMAGE
ARG UPSTREAM_REPOSITORY
ARG UPSTREAM_REVISION
ARG ASSET_PATH
ARG ASSET_SHA256
COPY --chown=0:0 asset/ ${ASSET_PATH}/
LABEL org.opencontainers.image.base.name="${UPSTREAM_IMAGE}" \
      dev.gstack.cso.upstream.repository="${UPSTREAM_REPOSITORY}" \
      dev.gstack.cso.upstream.revision="${UPSTREAM_REVISION}" \
      dev.gstack.cso.asset.path="${ASSET_PATH}" \
      dev.gstack.cso.asset.sha256="${ASSET_SHA256}"
