#!/usr/bin/env bash
set -euo pipefail

artifact_root="${CODEX_ARTIFACT_ROOT:-/root/codex_artifacts}"
block_mount="/mnt/volume_sfo2_1788290659423"

if [[ $# -lt 1 || $# -gt 2 ]]; then
    printf 'Usage: %s <target> [objective]\n' "$0" >&2
    exit 2
fi

if ! mountpoint -q "$block_mount"; then
    printf 'Refusing to create artifacts: block volume is not mounted at %s\n' "$block_mount" >&2
    exit 1
fi

resolved_root="$(realpath -e "$artifact_root")"
case "$resolved_root" in
    "$block_mount"/codex_artifacts) ;;
    *)
        printf 'Refusing to create artifacts outside the block volume: %s\n' "$resolved_root" >&2
        exit 1
        ;;
esac

slugify() {
    printf '%s' "$1" \
        | tr '[:upper:]' '[:lower:]' \
        | sed -E 's/[^a-z0-9._-]+/-/g; s/^-+//; s/-+$//'
}

target="$(slugify "$1")"
objective="$(slugify "${2:-hunt}")"

if [[ -z "$target" || -z "$objective" ]]; then
    printf 'Target and objective must contain a usable filename character.\n' >&2
    exit 2
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
output_dir="$artifact_root/hunts/$target/$timestamp-$objective"
install -d -m 0700 -- "$output_dir"
printf '%s\n' "$output_dir"
