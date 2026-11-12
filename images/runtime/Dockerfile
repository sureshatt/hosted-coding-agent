# Agent runtime: Claude Code plus what the fixture task needs, baked in, so a
# session never needs package registries or any other network access.
FROM node@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee
# node:22-bookworm-slim, pinned by digest

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pytest git ca-certificates curl dnsutils \
 && rm -rf /var/lib/apt/lists/*

# Pinned to a release at least two weeks old when chosen (2.1.312, 2026-10-27).
RUN npm install -g --no-fund --no-audit @anthropic-ai/claude-code@2.1.312 \
 && npm cache clean --force

# The node image's uid 1000 user is renamed to "agent". Claude Code refuses to
# skip permission prompts as root, and the agent has no reason to be root.
RUN usermod -l agent -d /home/agent -m node && groupmod -n agent node
COPY images/runtime/run-agent.sh /usr/local/bin/run-agent
USER agent
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/run-agent"]
