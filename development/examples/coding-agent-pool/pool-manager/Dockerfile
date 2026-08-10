FROM node:22-slim

WORKDIR /srv
COPY package.json server.mjs lease-token.mjs ./
RUN npm install

# The only difference from the code-reviewer-pool manager: which service it pools.
# run.sh sets no per-node env, so the pool name has to be baked into the image.
ENV SAM_POOL_SERVICE=coding-agent

EXPOSE 7780
CMD ["node", "server.mjs"]
