#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." >/dev/null && pwd)"
REMOTE_USER=${REMOTE_USER:-root}
REMOTE_HOST=${REMOTE_HOST:-68.183.103.58}
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
REMOTE_WEB_ROOT=${REMOTE_WEB_ROOT:-/var/www/chainprobe}
FRONTEND_DIR=${FRONTEND_DIR:-$REPO_ROOT/frontend}
API_URL=${API_URL:-http://68.183.103.58:3001/api}

if [ ! -d "$FRONTEND_DIR" ]; then
  echo "ERROR: frontend directory not found: $FRONTEND_DIR" >&2
  exit 1
fi

echo "Building frontend with API_URL=$API_URL"
pushd "$FRONTEND_DIR" > /dev/null
if [ -f pnpm-lock.yaml ]; then
  if command -v pnpm >/dev/null 2>&1; then
    pnpm install --frozen-lockfile
    pnpm build
  else
    echo "pnpm not installed; falling back to npm"
    npm ci
    npm run build
  fi
else
  npm ci
  npm run build
fi
popd > /dev/null

if [ "$REMOTE_HOST" = "localhost" ] || [ "$REMOTE_HOST" = "127.0.0.1" ]; then
  echo "Deploying frontend locally to $REMOTE_WEB_ROOT..."
  mkdir -p "$REMOTE_WEB_ROOT"
  rsync -av "$FRONTEND_DIR/build/" "$REMOTE_WEB_ROOT/"
  echo "Frontend deployed locally to $REMOTE_WEB_ROOT."
  exit 0
fi

echo "Creating remote web root..."
ssh -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" "mkdir -p $REMOTE_WEB_ROOT && chown $REMOTE_USER:$REMOTE_USER $REMOTE_WEB_ROOT"

echo "Uploading build... (uses build/ directory)"
rsync -avz -e "ssh -i $SSH_KEY" "$FRONTEND_DIR/build/" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_WEB_ROOT/"

echo "Frontend deployed. Ensure nginx is configured to serve $REMOTE_WEB_ROOT and proxy /api to the backend."
