#!/usr/bin/env bash
set -euo pipefail

REMOTE_USER=${REMOTE_USER:-root}
REMOTE_HOST=${REMOTE_HOST:-68.183.103.58}
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
REMOTE_WEB_ROOT=${REMOTE_WEB_ROOT:-/var/www/chainprobe}
FRONTEND_DIR=${FRONTEND_DIR:-frontend}
API_URL=${API_URL:-http://68.183.103.58:3001/api}

echo "Building frontend with API_URL=$API_URL"
pushd "$FRONTEND_DIR" > /dev/null
if [ -f pnpm-lock.yaml ]; then
  pnpm install --frozen-lockfile
  pnpm build
else
  npm ci
  npm run build
fi
popd > /dev/null

echo "Creating remote web root..."
ssh -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" "mkdir -p $REMOTE_WEB_ROOT && chown $REMOTE_USER:$REMOTE_USER $REMOTE_WEB_ROOT"

echo "Uploading build... (uses build/ directory)"
rsync -avz -e "ssh -i $SSH_KEY" "$FRONTEND_DIR/build/" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_WEB_ROOT/"

echo "Frontend deployed. Ensure nginx is configured to serve $REMOTE_WEB_ROOT and proxy /api to the backend."
