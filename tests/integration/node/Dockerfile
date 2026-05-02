# Node integration smoke. Build context = fasten repo root.
FROM node:24-alpine

WORKDIR /workspace

# SDK source goes side-by-side; rewrite the file: dependency to point at it.
COPY js/ /workspace/sdk-js/
COPY tests/integration/node/ /workspace/test/

RUN cd /workspace/test \
    && sed -i 's|file:../../../js|file:../sdk-js|' package.json \
    && npm install --no-audit --no-fund --silent

CMD ["node", "/workspace/test/smoke.mjs"]
