FROM node:20-bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates unzip \
  && rm -rf /var/lib/apt/lists/*

# Official Luau CLI (linux). Version must match a real GitHub release tag.
ARG LUAU_VERSION=0.738
RUN set -eux; \
  curl -fsSL -o /tmp/luau.zip \
    "https://github.com/luau-lang/luau/releases/download/${LUAU_VERSION}/luau-ubuntu.zip"; \
  mkdir -p /tmp/luau; \
  unzip -o /tmp/luau.zip -d /tmp/luau; \
  # zip layout can be flat or nested — find the `luau` binary
  LUAU_PATH="$(find /tmp/luau -type f -name luau | head -n 1)"; \
  test -n "$LUAU_PATH"; \
  install -m 755 "$LUAU_PATH" /usr/local/bin/luau; \
  ANALYZE_PATH="$(find /tmp/luau -type f -name luau-analyze | head -n 1 || true)"; \
  if [ -n "$ANALYZE_PATH" ]; then install -m 755 "$ANALYZE_PATH" /usr/local/bin/luau-analyze; fi; \
  rm -rf /tmp/luau /tmp/luau.zip; \
  test -x /usr/local/bin/luau; \
  # luau has no stable --version on all builds; don't fail the image build on flags
  /usr/local/bin/luau --help >/dev/null || true

COPY package.json ./
RUN npm install --omit=dev

COPY server.js leo_cli.luau ./

ENV LUAU_BIN=/usr/local/bin/luau
ENV PORT=3000
ENV DECOMPILE_TIMEOUT_MS=45000

EXPOSE 3000
CMD ["npm", "start"]
