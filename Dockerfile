FROM node:22.17.0-bookworm-slim

ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund \
    && npm cache clean --force

COPY --chown=node:node src/ ./src/
RUN mkdir -p /var/lib/agent-memory-fabric \
    && chown node:node /var/lib/agent-memory-fabric

USER node
EXPOSE 8787
CMD ["node", "src/server.mjs"]
