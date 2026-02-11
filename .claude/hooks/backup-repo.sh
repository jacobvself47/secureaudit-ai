#!/bin/bash
#
# Backup repository on Claude session start
# Keeps the last N backups (default: 10)

set -euo pipefail

BACKUP_DIR="${CLAUDE_BACKUP_DIR:-$HOME/.claude-backups}"
MAX_BACKUPS="${CLAUDE_MAX_BACKUPS:-10}"
PROJECT_NAME=$(basename "$CLAUDE_PROJECT_DIR")
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${PROJECT_NAME}_${TIMESTAMP}.tar.gz"

mkdir -p "$BACKUP_DIR"

# Create backup (exclude common large/generated directories)
tar -czf "$BACKUP_DIR/$BACKUP_FILE" \
    -C "$(dirname "$CLAUDE_PROJECT_DIR")" \
    --exclude='.git' \
    --exclude='node_modules' \
    --exclude='vendor' \
    --exclude='venv' \
    --exclude='.venv' \
    --exclude='__pycache__' \
    --exclude='.terraform' \
    --exclude='dist' \
    --exclude='build' \
    "$PROJECT_NAME" 2>/dev/null || true

# Cleanup old backups, keep last N
cd "$BACKUP_DIR"
ls -t "${PROJECT_NAME}"_*.tar.gz 2>/dev/null | tail -n +$((MAX_BACKUPS + 1)) | xargs -r rm -f

echo "Backup: $BACKUP_FILE (keeping last $MAX_BACKUPS)"
