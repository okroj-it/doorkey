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

# Numeric, not `bun`: with runAsNonRoot the kubelet cannot verify a named
# user and refuses to start the container.
USER 1000:1000
EXPOSE 8080
CMD ["bun", "src/index.ts"]
