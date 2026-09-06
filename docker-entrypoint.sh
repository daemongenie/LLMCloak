#!/bin/sh
# LLMCloak docker entrypoint — Quantum Sphere EOOD
# SPDX-License-Identifier: MIT
#
# If the container starts as root (the default), fix /data ownership so any
# host bind-mount works regardless of who owns the host directory, then drop
# privileges to the unprivileged app user (uid/gid 10001) and exec the service.
# If started with an explicit `docker run --user ...`, exec unchanged.

set -eu

if [ "$(id -u)" = "0" ]; then
    [ -d /data ] || mkdir -p /data
    chown -R 10001:10001 /data || true
    exec setpriv --reuid=10001 --regid=10001 --clear-groups "$@"
fi

exec "$@"
