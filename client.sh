#!/usr/bin/env bash
# Wrapper for edges/client.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/edges/client.sh" "$@"
