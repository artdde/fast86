#!/usr/bin/env bash
# Thin wrapper around /opt/macos-vm/start.sh (TCG Sequoia recovery, no KVM).
exec /opt/macos-vm/start.sh "$@"
