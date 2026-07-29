#!/bin/sh
set -eu

usage() {
    echo "usage: scripts/install.sh [--binary PATH] [--skill-dir DIRECTORY]" >&2
    exit 2
}

binary=""
skill_dir=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --binary)
            [ "$#" -ge 2 ] || usage
            binary=$2
            shift 2
            ;;
        --skill-dir)
            [ "$#" -ge 2 ] || usage
            skill_dir=$2
            shift 2
            ;;
        *) usage ;;
    esac
done

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ -z "$binary" ]; then
    command -v go >/dev/null 2>&1 || { echo "go is required when --binary is omitted" >&2; exit 1; }
    temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/aegis-install.XXXXXX")
    trap 'rm -rf "$temp_dir"' EXIT HUP INT TERM
    binary="$temp_dir/aegis-ssh"
    (cd "$root" && go build -trimpath -o "$binary" ./cmd/aegis-ssh)
fi
[ -f "$binary" ] || { echo "binary not found" >&2; exit 1; }

bin_dir=${XDG_BIN_HOME:-"$HOME/.local/bin"}
mkdir -p "$bin_dir"
install -m 0755 "$binary" "$bin_dir/aegis-ssh"

if [ -n "$skill_dir" ]; then
    destination="$skill_dir/aegis-ssh"
    mkdir -p "$destination"
    cp -R "$root/skills/aegis-ssh/." "$destination/"
fi

echo "installed $bin_dir/aegis-ssh"
