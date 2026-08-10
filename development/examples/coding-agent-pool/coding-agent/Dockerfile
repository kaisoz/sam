FROM node:22-slim

# The coding agent: Google's Gemini CLI. git is what makes reset/diff possible.
RUN apt-get update && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*
RUN npm install -g @google/gemini-cli

WORKDIR /srv
COPY package.json agent_server.mjs lease-token.mjs ./
RUN npm install

# The warm part: workspace baked in, deps installed, committed as the baseline
# each task resets to.
COPY workspace /work
RUN cd /work && npm install --no-audit --no-fund \
 && git init -q \
 && git config user.email dev@example.com \
 && git config user.name dev \
 && git add -A && git commit -qm baseline

# Dev-only: replace <API_KEY> with a Google AI Studio free-tier key before `make kind`.
# Keep the edit local so it is never committed:
#   git update-index --skip-worktree development/examples/coding-agent-pool/coding-agent/Dockerfile
ENV GEMINI_API_KEY=<API_KEY>
ENV GEMINI_CLI_TRUST_WORKSPACE=true
ENV SAM_WORKSPACE=/work

EXPOSE 7781
CMD ["node", "agent_server.mjs"]
