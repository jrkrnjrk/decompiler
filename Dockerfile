FROM node:20-bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates unzip zstd \
  && rm -rf /var/lib/apt/lists/*

# Official Luau CLI (linux). Version must match a real GitHub release tag.
ARG LUAU_VERSION=0.738
RUN set -eux; \
  curl -fsSL -o /tmp/luau.zip \
    "https://github.com/luau-lang/luau/releases/download/${LUAU_VERSION}/luau-ubuntu.zip"; \
  mkdir -p /tmp/luau; \
  unzip -o /tmp/luau.zip -d /tmp/luau; \
  LUAU_PATH="$(find /tmp/luau -type f -name luau | head -n 1)"; \
  test -n "$LUAU_PATH"; \
  install -m 755 "$LUAU_PATH" /usr/local/bin/luau; \
  ANALYZE_PATH="$(find /tmp/luau -type f -name luau-analyze | head -n 1 || true)"; \
  if [ -n "$ANALYZE_PATH" ]; then install -m 755 "$ANALYZE_PATH" /usr/local/bin/luau-analyze; fi; \
  rm -rf /tmp/luau /tmp/luau.zip; \
  test -x /usr/local/bin/luau; \
  /usr/local/bin/luau --help >/dev/null || true

COPY package.json ./
RUN npm install --omit=dev

COPY server.js formats.js leo_cli.luau ./

ENV LUAU_BIN=/usr/local/bin/luau
ENV PORT=3000
ENV DECOMPILE_TIMEOUT_MS=45000
ENV MAX_BODY_BYTES=33554432

EXPOSE 3000
CMD ["npm", "start"]
