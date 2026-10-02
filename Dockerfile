# --- build the keypad ------------------------------------------------------
# Keep in step with "packageManager" in package.json (what CI runs).
FROM oven/bun:1.4.2-alpine AS web
WORKDIR /build/web
COPY web/package.json web/bun.lock* ./
RUN bun install --frozen-lockfile
COPY web/ ./
RUN bun run build

# --- runtime ---------------------------------------------------------------
FROM oven/bun:1.4.2-alpine
WORKDIR /app

COPY package.json bun.lock* ./
RUN bun install --frozen-lockfile --production

COPY src/ ./src/
COPY cli/ ./cli/
COPY db/ ./db/
COPY --from=web /build/web/dist/ ./web/dist/
COPY --from=web /build/web/dist-admin/ ./web/dist-admin/
COPY --from=web /build/web/dist-action/ ./web/dist-action/

# Set by the release workflow; a local build is "dev". BUILD_ARCH uses Home
# Assistant's names (amd64, aarch64).
ARG BUILD_VERSION=dev
ARG BUILD_ARCH=amd64
LABEL org.opencontainers.image.source="https://github.com/okroj-it/doorkey" \
      org.opencontainers.image.description="Phone keypad for the front door from an NFC tap, and fingerprint-confirmed Home Assistant actions" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${BUILD_VERSION}" \
      io.hass.type="app" \
      io.hass.name="doorkey" \
      io.hass.description="Phone keypad for the front door, and fingerprint-confirmed actions" \
      io.hass.version="${BUILD_VERSION}" \
      io.hass.arch="${BUILD_ARCH}"

# Numeric, not `bun`: with runAsNonRoot the kubelet cannot verify a named
# user and refuses to start the container.
USER 1000:1000
EXPOSE 8080
CMD ["bun", "src/index.ts"]
