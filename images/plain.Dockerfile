# A reviewed upstream scanner image, re-published unchanged except for labels so
# that this repository's workflow can sign SLSA provenance and an SPDX SBOM for it.
ARG UPSTREAM_IMAGE
FROM ${UPSTREAM_IMAGE}
ARG UPSTREAM_IMAGE
ARG UPSTREAM_REPOSITORY
ARG UPSTREAM_REVISION
LABEL org.opencontainers.image.base.name="${UPSTREAM_IMAGE}" \
      dev.gstack.cso.upstream.repository="${UPSTREAM_REPOSITORY}" \
      dev.gstack.cso.upstream.revision="${UPSTREAM_REVISION}"
