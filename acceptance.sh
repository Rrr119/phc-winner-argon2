#!/bin/sh
#
# One-command adaptive-Argon2 acceptance:
#   - resets the JSON-lines audit log so the event sequence is deterministic
#   - builds and runs the 264-check acceptance suite via make
#   - refreshes the audit-log evidence under artifacts/ when possible
#
# Usage: ./acceptance.sh

set -eu

cd "$(dirname "$0")"

AUDIT_LOG="argon2_param_audit.log"

: > "$AUDIT_LOG"

make test-adaptive

if [ -d artifacts ]; then
    cp "$AUDIT_LOG" artifacts/argon2_param_audit.log
fi
