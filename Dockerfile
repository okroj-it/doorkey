# --- build the keypad ------------------------------------------------------
# Keep in step with "packageManager" in package.json (what CI runs).
FROM oven/bun:1.4.2-alpine AS web
WORKDIR /build/web
COPY web/package.json web/bun.lock* ./
RUN bun install --frozen-lockfile
COPY web/ ./
RUN bun run build

# --- application files, shared by both images ----------------------------
FROM oven/bun:1.4.2-alpine AS base
WORKDIR /app

COPY package.json bun.lock* ./
RUN bun install --frozen-lockfile --production

COPY src/ ./src/
COPY cli/ ./cli/
COPY db/ ./db/
COPY --from=web /build/web/dist/ ./web/dist/
COPY --from=web /build/web/dist-admin/ ./web/dist-admin/
COPY --from=web /build/web/dist-action/ ./web/dist-action/

# --- Home Assistant app (docker build --target app) -------------------------
# The same files, started as root only to hand the Supervisor's root-owned
# /data to the doorkey user, which then runs doorkey
# (deploy/home-assistant/entrypoint.sh).
FROM base AS app
# Root on purpose, see above; doorkey itself never runs as root. su-exec is
# left unpinned: Alpine drops old package versions, so a pin breaks builds.
# hadolint ignore=DL3002
USER 0
# hadolint ignore=DL3018
RUN apk add --no-cache su-exec
COPY deploy/home-assistant/entrypoint.sh /usr/local/bin/doorkey-entrypoint
COPY deploy/home-assistant/doorkey /usr/local/bin/doorkey

# BUILD_ARCH uses Home Assistant's names (amd64, aarch64).
ARG BUILD_VERSION=dev
ARG BUILD_ARCH=amd64
LABEL org.opencontainers.image.source="https://github.com/okroj-it/doorkey" \
      org.opencontainers.image.description="doorkey as a Home Assistant app" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${BUILD_VERSION}" \
      io.hass.type="app" \
      io.hass.name="doorkey" \
      io.hass.description="Phone keypad for the front door, and fingerprint-confirmed actions" \
      io.hass.version="${BUILD_VERSION}" \
      io.hass.arch="${BUILD_ARCH}"

EXPOSE 8080 8099
ENTRYPOINT ["doorkey-entrypoint"]
CMD ["bun", "src/index.ts"]

# --- standalone image: compose, Kubernetes (the default target) ------------
FROM base AS runtime
# Set by the release workflow; a local build is "dev".
ARG BUILD_VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/okroj-it/doorkey" \
      org.opencontainers.image.description="Phone keypad for the front door from an NFC tap, and fingerprint-confirmed Home Assistant actions" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${BUILD_VERSION}"

# Numeric, not `bun`: with runAsNonRoot the kubelet cannot verify a named
# user and refuses to start the container.
USER 1000:1000
EXPOSE 8080
CMD ["bun", "src/index.ts"]

