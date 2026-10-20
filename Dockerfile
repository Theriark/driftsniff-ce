# driftsniff CE container image.
#
# Stage one downloads wheels for the hash-locked requirements (--require-hashes, binary wheels
# only, so no compiler is needed). The final stage installs only those wheels and the application.
# No credential is baked in: the master key and the database live on the /keys and /data volumes.

FROM python:3.12-slim-bookworm AS wheels

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY requirements.txt ./
RUN python -m pip wheel \
        --require-hashes \
        --only-binary=:all: \
        --no-deps \
        --wheel-dir /wheels \
        --requirement requirements.txt


FROM python:3.12-slim-bookworm AS runtime

ARG SOURCE_SHA=unknown

LABEL org.opencontainers.image.title="driftsniff" \
      org.opencontainers.image.source="https://github.com/Theriark/driftsniff-ce" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="${SOURCE_SHA}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

# Fixed ids so volume ownership is the same on every host. /keys and /data are the only
# writable places besides the /tmp tmpfs; the root file system is run read-only.
RUN groupadd --gid 10001 driftsniff \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin driftsniff \
    && install --directory --owner 10001 --group 10001 --mode 0700 /data /keys

# Install only the locked wheels (no index access, hashes enforced), then drop pip itself.
RUN --mount=type=bind,from=wheels,source=/wheels,target=/wheels \
    --mount=type=bind,source=requirements.txt,target=/requirements.txt \
    python -m pip install \
        --no-index \
        --find-links /wheels \
        --require-hashes \
        --no-deps \
        --no-cache-dir \
        --requirement /requirements.txt \
    && python -m pip uninstall --yes pip

WORKDIR /app
COPY src /app/src
COPY LICENSE /licenses/driftsniff-LICENSE

USER 10001:10001
VOLUME ["/data", "/keys"]
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["python", "-m", "driftsniff", "healthcheck"]

ENTRYPOINT ["python", "-m", "driftsniff", "serve"]
