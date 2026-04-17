#!/bin/bash
sudo ip link add bridge-tap type bridge
sudo ip link set bridge-tap up
sudo ip tuntap add dev tap0 mode tap
sudo ip link set tap0 master bridge-tap
sudo ip link set tap0 up
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Get the parent directory
PARENT_DIR="$(dirname "$SCRIPT_DIR")"

# Change to parent directory so all commands run from there
cd "$PARENT_DIR" || exit 1



docker build ./attack/target-server  -t servidor_alvo:latest --no-cache




docker build ./attack/attack_test -t atacante:latest --no-cache
