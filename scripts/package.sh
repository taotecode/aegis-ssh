#!/bin/sh
set -eu

[ "$#" -eq 1 ] || { echo "usage: scripts/package.sh OUTPUT_DIR" >&2; exit 2; }
output=$1
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
version=$(cd "$root" && git describe --tags --always --dirty 2>/dev/null || true)
[ -n "$version" ] || { echo "unable to determine worktree version" >&2; exit 1; }

mkdir -p "$output"
output=$(CDPATH='' cd -- "$output" && pwd)
stage=$(mktemp -d "${TMPDIR:-/tmp}/aegis-package.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
manifest="$stage/archives"
: > "$manifest"

for target in darwin-amd64 darwin-arm64 linux-amd64 linux-arm64; do
    os=${target%-*}
    arch=${target#*-}
    name="aegis-ssh-$version-$target"
    directory="$stage/$name"
    mkdir -p "$directory/docs" "$directory/skills"
    (cd "$root" && CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w" -o "$directory/aegis-ssh" ./cmd/aegis-ssh)
    cp "$root/README.md" "$root/README.zh-CN.md" "$root/SECURITY.md" "$root/SECURITY.zh-CN.md" "$root/LICENSE" "$directory/"
    cp "$root/docs/server-setup.md" "$root/docs/server-setup.zh-CN.md" "$directory/docs/"
    cp -R "$root/skills/aegis-ssh" "$directory/skills/"
    (cd "$stage" && tar -czf "$output/$name.tar.gz" "$name")
    echo "$name.tar.gz" >> "$manifest"
done

LC_ALL=C sort -o "$manifest" "$manifest"

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$output" && xargs sha256sum < "$manifest") > "$output/SHA256SUMS"
elif command -v shasum >/dev/null 2>&1; then
    (cd "$output" && xargs shasum -a 256 < "$manifest") > "$output/SHA256SUMS"
else
    echo "sha256sum or shasum is required" >&2
    exit 1
fi
