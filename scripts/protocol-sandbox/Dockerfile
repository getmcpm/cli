FROM node:26.11.1-bookworm-slim@sha256:86f07bc9c5dce4578cf37e5a418b7bfc7f817cda25cde66e2b66e95ed86c4567
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund && npm cache clean --force
RUN mkdir /evidence && chown 1000:1000 /evidence
COPY harness.mjs self-check.mjs peer.mjs run.mjs ./
COPY fixtures ./fixtures
ENV HOME=/work/home TMPDIR=/work
USER 1000:1000
WORKDIR /work
CMD ["sh", "-c", "node --test /app/self-check.mjs && node /app/run.mjs"]
