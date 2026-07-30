#!/bin/sh
set -eu

usage() {
    echo "usage: scripts/install.sh [install|update|uninstall] [--binary PATH] [--skill-dir DIRECTORY] [--version VERSION] [--purge]" >&2
    exit 2
}

binary=""
skill_dir=${CODEX_HOME:-"$HOME/.codex"}/skills
action=install
version=latest
purge=false
case "${1:-}" in install|update|uninstall) action=$1; shift ;; esac
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
        --version)
            [ "$#" -ge 2 ] || usage
            version=$2
            shift 2
            ;;
        --purge) purge=true; shift ;;
        *) usage ;;
    esac
done

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
bin_dir=${XDG_BIN_HOME:-"$HOME/.local/bin"}
if [ "$action" = uninstall ]; then
    command -v aegis-ssh >/dev/null 2>&1 && aegis-ssh stop >/dev/null 2>&1 || true
    rm -f "$bin_dir/aegis-ssh"
    if [ -n "$skill_dir" ]; then rm -rf "$skill_dir/aegis-ssh"; fi
    if [ "$purge" = true ]; then
        printf 'Type PURGE to permanently remove ~/.aegis-ssh: ' >/dev/tty
        IFS= read -r answer </dev/tty
        [ "$answer" = PURGE ] || { echo "purge canceled"; exit 1; }
        rm -rf "$HOME/.aegis-ssh"
    fi
    echo "aegis-ssh uninstalled; encrypted user data was preserved unless --purge was confirmed"
    exit 0
fi
if [ "$action" = update ] && command -v aegis-ssh >/dev/null 2>&1; then
    aegis-ssh stop >/dev/null 2>&1 || true
fi
if [ -z "$binary" ]; then
    temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/aegis-install.XXXXXX")
    trap 'rm -rf "$temp_dir"' EXIT HUP INT TERM
    if command -v go >/dev/null 2>&1 && [ -f "$root/go.mod" ]; then
        binary="$temp_dir/aegis-ssh"
        (cd "$root" && go build -trimpath -o "$binary" ./cmd/aegis-ssh)
    else
        command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
        os=$(uname -s | tr '[:upper:]' '[:lower:]'); arch=$(uname -m)
        case "$arch" in x86_64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; *) echo "unsupported architecture" >&2; exit 1 ;; esac
        if [ "$version" = latest ]; then version=$(curl -fsSL https://api.github.com/repos/taotecode/aegis-ssh/releases/latest | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1); fi
        archive="aegis-ssh-$version-$os-$arch.tar.gz"
        base="https://github.com/taotecode/aegis-ssh/releases/download/$version"
        curl -fL "$base/$archive" -o "$temp_dir/$archive"
        curl -fL "$base/SHA256SUMS" -o "$temp_dir/SHA256SUMS"
        (cd "$temp_dir" && grep " $archive$" SHA256SUMS | { command -v sha256sum >/dev/null 2>&1 && sha256sum -c - || shasum -a 256 -c -; })
        tar -xzf "$temp_dir/$archive" -C "$temp_dir"
        binary=$(find "$temp_dir" -type f -name aegis-ssh | head -n 1)
    fi
fi
[ -f "$binary" ] || { echo "binary not found" >&2; exit 1; }

mkdir -p "$bin_dir"
install -m 0755 "$binary" "$bin_dir/.aegis-ssh.new"
mv "$bin_dir/.aegis-ssh.new" "$bin_dir/aegis-ssh"

if [ -n "$skill_dir" ]; then
    destination="$skill_dir/aegis-ssh"
    mkdir -p "$destination"
    source_root=$root
    binary_root=$(CDPATH='' cd -- "$(dirname -- "$binary")" && pwd)
    if [ -d "$binary_root/skills/aegis-ssh" ]; then source_root=$binary_root; fi
    cp -R "$source_root/skills/aegis-ssh/." "$destination/"
fi

echo "$action complete: $bin_dir/aegis-ssh"
if [ "$action" = update ]; then echo "run 'aegis-ssh start' to launch the updated locked broker"; fi
