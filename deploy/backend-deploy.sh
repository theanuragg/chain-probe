#!/usr/bin/env bash
set -euo pipefail

REMOTE_USER=${REMOTE_USER:-root}
REMOTE_HOST=${REMOTE_HOST:-68.183.103.58}
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
REMOTE_PATH=${REMOTE_PATH:-/opt/chainprobe}
BUILD_DIR=${BUILD_DIR:-backend}

echo "Building backend release..."
pushd "$BUILD_DIR" > /dev/null
cargo build --release
popd > /dev/null

echo "Creating remote directory..."
ssh -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" "mkdir -p $REMOTE_PATH && chown $REMOTE_USER:$REMOTE_USER $REMOTE_PATH"

echo "Copying binary..."
scp -i "$SSH_KEY" "$BUILD_DIR/target/release/chainprobe" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH/chainprobe"

echo "Uploading systemd unit..."
scp -i "$SSH_KEY" /Users/anurag/coding/chainprobe-v4/deploy/systemd/chainprobe.service "$REMOTE_USER@$REMOTE_HOST:/etc/systemd/system/chainprobe.service"

echo "Reloading systemd, enabling and starting service..."
ssh -i "$SSH_KEY" "$REMOTE_USER@$REMOTE_HOST" "systemctl daemon-reload && systemctl enable --now chainprobe"

echo "Backend deployed and started."
