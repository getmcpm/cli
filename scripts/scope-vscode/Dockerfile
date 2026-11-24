FROM node:26.11.1-bookworm-slim@sha256:86f07bc9c5dce4578cf37e5a418b7bfc7f817cda25cde66e2b66e95ed86c4567
RUN apt-get update && apt-get install -y --no-install-recommends \
    xvfb libgtk-3-0 libnss3 libasound2 libxss1 libgbm1 libx11-xcb1 \
    libatk-bridge2.0-0 libxkbcommon0 libdrm2 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# These are the existing protocol manifest/lock with only the explicit candidate file overlay.
COPY package.json package-lock.json candidate.tgz candidate.json inputs.json ./
RUN npm install --package-lock-only --ignore-scripts --no-audit --no-fund \
    && npm ci --ignore-scripts --no-audit --no-fund && npm cache clean --force
COPY vscode /opt/vscode
COPY run.mjs check.mjs extension.cjs ./
RUN mkdir /evidence && chown 1000:1000 /evidence
USER 1000:1000
ENV HOME=/home/node TMPDIR=/work/tmp
WORKDIR /work
CMD ["node", "/app/run.mjs"]
