FROM node:26.11.1-bookworm-slim@sha256:86f07bc9c5dce4578cf37e5a418b7bfc7f817cda25cde66e2b66e95ed86c4567
COPY native /opt/claude
RUN chmod 0755 /opt/claude && mkdir /evidence && chown 1000:1000 /evidence
COPY plugin-lifecycle-run.mjs plugin-lifecycle-checks.mjs plugin-lifecycle-pins.json inputs.json /probe/
COPY plugin-lifecycle-marker.mjs /probe/marker.mjs
COPY plugin-lifecycle-fixtures /probe/plugin-lifecycle-fixtures
ENV HOME=/work/home TMPDIR=/work
USER 1000:1000
WORKDIR /work
CMD ["node", "/probe/plugin-lifecycle-run.mjs"]
