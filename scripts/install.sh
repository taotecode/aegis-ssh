#!/bin/sh
set -eu

usage() {
    echo "usage: scripts/install.sh [install|update|uninstall] [--binary PATH|--source] [--version VERSION] [--skill-dir DIRECTORY] [--purge]" >&2
    exit 2
}

action=install
binary=""
version=latest
build_from_source=false
purge=false
legacy_skill_dir=""
case "${1:-}" in install|update|uninstall) action=$1; shift ;; esac
while [ "$#" -gt 0 ]; do
    case "$1" in
        --binary)
            [ "$#" -ge 2 ] || usage
            binary=$2
            shift 2
            ;;
        --source) build_from_source=true; shift ;;
        --version)
            [ "$#" -ge 2 ] || usage
            version=$2
            shift 2
            ;;
        --skill-dir)
            [ "$#" -ge 2 ] || usage
            legacy_skill_dir=$2
            shift 2
            ;;
        --purge) purge=true; shift ;;
        *) usage ;;
    esac
done
[ -z "$binary" ] || [ "$build_from_source" = false ] || usage

root=""
if [ -f "$0" ]; then
    root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
fi
bin_dir=${XDG_BIN_HOME:-"$HOME/.local/bin"}
installed_binary="$bin_dir/aegis-ssh"

ensure_default_bin_path() {
    [ "$bin_dir" = "$HOME/.local/bin" ] || return 0
    case ":${PATH:-}:" in *":$bin_dir:"*) return 0 ;; esac
    case "${SHELL:-}" in
        */zsh) profile="$HOME/.zshrc" ;;
        */bash) profile="$HOME/.bashrc" ;;
        *) profile="$HOME/.profile" ;;
    esac
    path_line="export PATH=\"\$HOME/.local/bin:\$PATH\""
    if ! grep -Fqx "$path_line" "$profile" 2>/dev/null; then
        printf '\n# Added by the Aegis SSH installer.\n%s\n' "$path_line" >> "$profile"
        echo "added $bin_dir to PATH in $profile; open a new terminal to use aegis-ssh"
    fi
}

if [ "$action" = uninstall ]; then
    agent_failed=false
    if [ -x "$installed_binary" ]; then
        if "$installed_binary" --help 2>/dev/null | grep -q 'agent configure'; then
            "$installed_binary" agent unconfigure auto || agent_failed=true
        else
            echo "warning: installed version cannot automatically remove Agent integrations" >&2
        fi
        "$installed_binary" stop >/dev/null 2>&1 || true
    fi
    rm -f "$installed_binary"
    if [ "$purge" = true ]; then
        printf 'Type PURGE to permanently remove ~/.aegis-ssh: ' >/dev/tty
        IFS= read -r answer </dev/tty
        [ "$answer" = PURGE ] || { echo "purge canceled"; exit 1; }
        rm -rf "$HOME/.aegis-ssh"
    fi
    echo "aegis-ssh uninstalled; encrypted user data was preserved unless --purge was confirmed"
    [ "$agent_failed" = false ] || {
        echo "some Agent integrations could not be removed" >&2
        exit 1
    }
    exit 0
fi

temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/aegis-install.XXXXXX")
trap 'rm -rf "$temp_dir"' EXIT HUP INT TERM

if [ -n "$binary" ]; then
    :
elif [ "$build_from_source" = true ]; then
    command -v go >/dev/null 2>&1 || { echo "go is required for --source" >&2; exit 1; }
    [ -n "$root" ] && [ -f "$root/go.mod" ] || {
        echo "--source must run from scripts/install.sh in an Aegis SSH source checkout" >&2
        exit 1
    }
    binary="$temp_dir/aegis-ssh"
    (cd "$root" && go build -trimpath -o "$binary" ./cmd/aegis-ssh)
else
    command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$os" in darwin|linux) ;; *) echo "unsupported operating system: $os" >&2; exit 1 ;; esac
    arch=$(uname -m)
    case "$arch" in
        x86_64) arch=amd64 ;;
        arm64|aarch64) arch=arm64 ;;
        *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
    esac
    if [ "$version" = latest ]; then
        version=$(curl -fsSL https://api.github.com/repos/taotecode/aegis-ssh/releases/latest | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
        [ -n "$version" ] || { echo "unable to determine latest release" >&2; exit 1; }
    fi
    archive="aegis-ssh-$version-$os-$arch.tar.gz"
    base="https://github.com/taotecode/aegis-ssh/releases/download/$version"
    curl -fL "$base/$archive" -o "$temp_dir/$archive"
    curl -fL "$base/SHA256SUMS" -o "$temp_dir/SHA256SUMS"
    grep " $archive$" "$temp_dir/SHA256SUMS" > "$temp_dir/CHECKSUM"
    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$temp_dir" && sha256sum -c CHECKSUM)
    else
        command -v shasum >/dev/null 2>&1 || { echo "sha256sum or shasum is required" >&2; exit 1; }
        (cd "$temp_dir" && shasum -a 256 -c CHECKSUM)
    fi
    tar -xzf "$temp_dir/$archive" -C "$temp_dir"
    binary="$temp_dir/aegis-ssh-$version-$os-$arch/aegis-ssh"
fi
[ -f "$binary" ] || { echo "binary not found: $binary" >&2; exit 1; }
[ -x "$binary" ] || { echo "binary is not executable: $binary" >&2; exit 1; }
"$binary" --help >/dev/null 2>&1 || { echo "binary validation failed: $binary" >&2; exit 1; }

was_running=false
if [ "$action" = update ] && [ -x "$installed_binary" ]; then
    if "$installed_binary" status 2>/dev/null | grep -Eq '^daemon: (ready|locked)$|^后台服务：(就绪|已锁定)$'; then
        was_running=true
    fi
    "$installed_binary" stop >/dev/null 2>&1 || true
fi

mkdir -p "$bin_dir"
install -m 0755 "$binary" "$bin_dir/.aegis-ssh.new"
mv "$bin_dir/.aegis-ssh.new" "$installed_binary"
echo "$action complete: $installed_binary"
ensure_default_bin_path

if [ -n "$legacy_skill_dir" ]; then
    echo "warning: --skill-dir is deprecated; Agent Skill installation is managed automatically" >&2
fi

agent_failed=false
"$installed_binary" agent configure auto || agent_failed=true

restart_failed=false
if [ "$was_running" = true ]; then
    if "$installed_binary" start-locked >/dev/null 2>&1; then
        echo "broker restarted locked; run 'aegis-ssh unlock' to resume"
    else
        restart_failed=true
        echo "updated binary installed, but the locked broker could not be restarted" >&2
    fi
fi

if [ "$agent_failed" = true ]; then
    echo "some Agent integrations failed; run 'aegis-ssh agent status'" >&2
fi
[ "$agent_failed" = false ] && [ "$restart_failed" = false ]
