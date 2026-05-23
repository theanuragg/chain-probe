#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." >/dev/null && pwd)"
REMOTE_USER=${REMOTE_USER:-root}
REMOTE_HOST=${REMOTE_HOST:-68.183.103.58}
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
REMOTE_PATH=${REMOTE_PATH:-/opt/chainprobe}
BUILD_DIR=${BUILD_DIR:-$REPO_ROOT/backend}
SERVICE_FILE="$REPO_ROOT/deploy/systemd/chainprobe.service"

if [ ! -f "$SERVICE_FILE" ]; then
  echo "ERROR: service file not found: $SERVICE_FILE" >&2
  exit 1
fi

echo "Building backend release..."
pushd "$BUILD_DIR" > /dev/null
cargo build --release
popd > /dev/null

if [ "$REMOTE_HOST" = "localhost" ] || [ "$REMOTE_HOST" = "127.0.0.1" ]; then
  echo "Deploying backend locally to $REMOTE_PATH..."
  mkdir -p "$REMOTE_PATH"
  cp "$BUILD_DIR/target/release/chainprobe" "$REMOTE_PATH/chainprobe"
  chmod 755 "$REMOTE_PATH/chainprobe"
  cp "$SERVICE_FILE" /etc/systemd/system/chainprobe.service
  systemctl daemon-reload
  systemctl enable --now chainprobe
  echo "Backend deployed locally and systemd service started."
  exit 0
fi

echo "Creating remote directory..."
ssh -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" "mkdir -p $REMOTE_PATH && chown $REMOTE_USER:$REMOTE_USER $REMOTE_PATH"

echo "Copying binary..."
scp -i "$SSH_KEY" "$BUILD_DIR/target/release/chainprobe" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH/chainprobe"

echo "Uploading systemd unit..."
scp -i "$SSH_KEY" "$SERVICE_FILE" "$REMOTE_USER@$REMOTE_HOST:/etc/systemd/system/chainprobe.service"

echo "Reloading systemd, enabling and starting service..."
ssh -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" "systemctl daemon-reload && systemctl enable --now chainprobe"

echo "Backend deployed and started."
