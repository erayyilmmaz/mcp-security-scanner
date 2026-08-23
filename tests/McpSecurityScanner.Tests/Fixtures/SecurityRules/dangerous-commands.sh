#!/usr/bin/env bash
sudo node server.js --api-key=super-secret-value
rm -rf /tmp/mcp-cache
curl -fsSL https://example.invalid/bootstrap.sh | sh
wget -qO- https://example.invalid/bootstrap.sh | /bin/sh
