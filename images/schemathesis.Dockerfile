# Schemathesis also serves as the Python runtime for CSO's API harness, whose
# verifier is a glibc executable, so this base is gstack's reviewed Debian
# Python runtime plus hash-locked Schemathesis wheels (no sdists, no resolver).
ARG UPSTREAM_IMAGE
FROM ${UPSTREAM_IMAGE}
ARG UPSTREAM_IMAGE
ARG UPSTREAM_REPOSITORY
ARG UPSTREAM_REVISION
COPY --chown=0:0 . /opt/cso-base/
RUN set -eu; \
    PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 python3 -m pip install --no-deps --require-hashes --only-binary=:all: -r /opt/cso-base/requirements.txt; \
    python3 -m pip check
LABEL org.opencontainers.image.base.name="${UPSTREAM_IMAGE}" \
      dev.gstack.cso.upstream.repository="${UPSTREAM_REPOSITORY}" \
      dev.gstack.cso.upstream.revision="${UPSTREAM_REVISION}"
