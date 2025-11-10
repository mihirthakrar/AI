# Python-based MCP SSH Tools Server (stdio)
# Minimal image that runs the Python MCP server over stdio for VS Code + Cline.

FROM python:3.11-slim

# Optional corporate proxy build args
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

# Propagate proxies for pip if provided
ENV HTTP_PROXY=${HTTP_PROXY} \
    HTTPS_PROXY=${HTTPS_PROXY} \
    NO_PROXY=${NO_PROXY} \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies
# - Upgrade pip and install only the two runtime deps:
#   mcp: Python SDK for Model Context Protocol (stdio server)
#   paramiko: SSH client used by the tools
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir mcp paramiko

# Copy server code
COPY server.py /app/server.py

# Default command: run the MCP server over stdio
CMD ["python", "/app/server.py"]
