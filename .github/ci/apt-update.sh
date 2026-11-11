#!/usr/bin/env bash
# `apt-get update` for the Ubuntu CI jobs, falling back to community mirrors
# when Canonical's own hosts cannot be reached.
#
# On 2026-11-11 archive.ubuntu.com, security.ubuntu.com, ports.ubuntu.com and
# GitHub's azure.archive.ubuntu.com mirror all stopped resolving, while
# community mirrors kept serving current noble, noble-updates and
# noble-security indexes. Every job failed in its "install dependencies" step
# before building anything.
#
# The normal path is unchanged: when the configured sources update without an
# error, nothing is rewritten. Only on failure are the Canonical URIs (and the
# runner's mirror+file list) replaced by the fallback mirror and the update is
# retried. Third-party sources are never touched. Override the mirrors with
# APT_FALLBACK_MIRROR (amd64) or APT_FALLBACK_PORTS_MIRROR (other arches).
set -euo pipefail

update() {
  # Error-Mode=any makes a failed index fetch an error, instead of a warning
  # that leaves stale lists and fails later at download time.
  sudo apt-get -o APT::Update::Error-Mode=any -o Acquire::Retries=3 update
}

if update; then
  exit 0
fi

arch=$(dpkg --print-architecture)
if [ "$arch" = amd64 ] || [ "$arch" = i386 ]; then
  mirror=${APT_FALLBACK_MIRROR:-https://mirrors.edge.kernel.org/ubuntu/}
else
  mirror=${APT_FALLBACK_PORTS_MIRROR:-https://ftp.tu-chemnitz.de/pub/linux/ubuntu-ports/}
fi
echo "::warning::Ubuntu package hosts unreachable; switching apt to $mirror"

shopt -s nullglob
for file in /etc/apt/sources.list /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list; do
  [ -f "$file" ] || continue
  sudo sed -E -i \
    -e "s#mirror\+file:/etc/apt/apt-mirrors\.txt/?#${mirror}#g" \
    -e "s#https?://([a-z0-9-]+\.)?(archive|security)\.ubuntu\.com/ubuntu/?#${mirror}#g" \
    -e "s#https?://ports\.ubuntu\.com/ubuntu-ports/?#${mirror}#g" \
    "$file"
done

update
