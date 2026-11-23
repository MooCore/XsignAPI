FROM node:22-bookworm-slim AS zsign-builder
ARG ZSIGN_REF=master
RUN apt-get update \
    && apt-get install -y --no-install-recommends git g++ make pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "${ZSIGN_REF}" https://github.com/zhlynn/zsign.git /tmp/zsign \
    && make -C /tmp/zsign/build/linux -j"$(nproc)" \
    && ZSIGN_BIN="$(find /tmp/zsign -type f -name zsign -perm -111 -print -quit)" \
    && test -n "$ZSIGN_BIN" \
    && install -m 0755 "$ZSIGN_BIN" /usr/local/bin/zsign

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production \
    PORT=10000 \
    SIGNING_TEMP_DIR=/tmp/xsign \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssl python3 unzip zip dpkg-dev libssl3 libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app /tmp/xsign \
    && chown -R node:node /app /tmp/xsign
WORKDIR /app
COPY --from=zsign-builder /usr/local/bin/zsign /usr/local/bin/zsign
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY --chown=node:node src ./src
COPY --chown=node:node scripts ./scripts
USER node
EXPOSE 10000
CMD ["npm", "start"]
