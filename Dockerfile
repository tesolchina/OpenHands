# syntax=docker/dockerfile:1.7

ARG AGENT_SERVER_IMAGE=ghcr.io/openhands/agent-server:1.39.1-python
ARG AUTOMATION_VERSION=1.5.0

FROM node:24-slim AS frontend-build
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ARG VITE_BASE_PATH="/"
ARG VITE_POSTHOG_API_KEY=""
ENV VITE_BASE_PATH=${VITE_BASE_PATH}
ENV VITE_POSTHOG_API_KEY=${VITE_POSTHOG_API_KEY}
RUN npm run build

FROM node:24-slim AS config-gen
COPY config/defaults.json /tmp/
RUN node -e " \
  const c = JSON.parse(require('fs').readFileSync('/tmp/defaults.json','utf-8')); \
  const lines = [ \
    'CONFIG_AGENT_SERVER_PORT=' + c.ports.agentServer, \
    'CONFIG_AUTOMATION_PORT=' + c.ports.automation, \
    'CONFIG_VSCODE_PORT=' + c.ports.vscode, \
    'CONFIG_PROXY_PORT=' + c.ports.proxy, \
    'CONFIG_STATE_SUBDIR=' + c.paths.stateSubdir, \
    'CONFIG_CONVERSATIONS=' + c.paths.conversations, \
    'CONFIG_BASH_EVENTS=' + c.paths.bashEvents, \
    'CONFIG_AUTOMATION_DB=' + c.paths.automationDb, \
    'CONFIG_CANVAS_BASE_PATH=' + (process.env.VITE_BASE_PATH || '/'), \
    'CONFIG_POSTHOG_API_KEY=' + c.telemetry.posthogApiKey, \
    'CONFIG_POSTHOG_HOST=' + c.telemetry.posthogHost, \
  ]; \
  require('fs').writeFileSync('/tmp/defaults.env', lines.join('\n') + '\n'); \
"

FROM ${AGENT_SERVER_IMAGE} AS final
ARG AUTOMATION_VERSION
ARG VITE_BASE_PATH="/"
ARG VITE_POSTHOG_API_KEY=""

ENV AGENT_CANVAS_BASE_PATH=${VITE_BASE_PATH}
ENV VITE_POSTHOG_API_KEY=${VITE_POSTHOG_API_KEY}

USER root
RUN if command -v apt-get >/dev/null 2>&1; then \
      apt-get update && \
      apt-get install -y --no-install-recommends libpq-dev && \
      rm -rf /var/lib/apt/lists/*; \
    fi

RUN uv pip install --system "openhands-automation==${AUTOMATION_VERSION}" 2>/dev/null \
    || pip install --no-cache-dir "openhands-automation==${AUTOMATION_VERSION}"

COPY --from=frontend-build /build/build /opt/agent-canvas/frontend
COPY scripts/static-server.mjs /opt/agent-canvas/static-server.mjs
COPY scripts/proxy-utils.mjs /opt/agent-canvas/proxy-utils.mjs
COPY --from=frontend-build /build/node_modules/httpxy /opt/agent-canvas/node_modules/httpxy
COPY --from=frontend-build /build/node_modules/sirv /opt/agent-canvas/node_modules/sirv
COPY --from=frontend-build /build/node_modules/@polka /opt/agent-canvas/node_modules/@polka
COPY --from=frontend-build /build/node_modules/mrmime /opt/agent-canvas/node_modules/mrmime
COPY --from=frontend-build /build/node_modules/totalist /opt/agent-canvas/node_modules/totalist
COPY scripts/runtime-services-info.mjs /opt/agent-canvas/runtime-services-info.mjs
COPY tools/ /opt/agent-canvas/tools/
COPY --from=config-gen /tmp/defaults.env /opt/agent-canvas/defaults.env
COPY docker/entrypoint.sh /opt/agent-canvas/entrypoint.sh
RUN chmod +x /opt/agent-canvas/entrypoint.sh

RUN mkdir -p /home/openhands/.openhands/agent-canvas/conversations \
             /home/openhands/.openhands/agent-canvas/bash_events \
             /home/openhands/.openhands/automation \
             /projects && \
    chown -R openhands:openhands /home/openhands/.openhands /projects

USER openhands
EXPOSE 8000
ENTRYPOINT ["tini", "--", "/opt/agent-canvas/entrypoint.sh"]
