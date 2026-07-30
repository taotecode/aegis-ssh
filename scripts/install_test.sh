#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/aegis-install-test.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
home="$work/home"
fixtures="$work/fixtures"
fake_bin="$work/bin"
stage="$work/aegis-ssh-v0.4.0-darwin-arm64"
mkdir -p "$home" "$fixtures" "$fake_bin" "$stage"

# shellcheck disable=SC2016
printf '%s\n' '#!/bin/sh' 'printf "%s\n" "$*" >> "$AEGIS_FAKE_LOG"' 'case "${1:-}" in' '  --help) echo "agent configure|unconfigure|status" ;;' '  status) echo "daemon: unavailable" ;;' 'esac' > "$stage/aegis-ssh"
chmod 0755 "$stage/aegis-ssh"
(cd "$work" && tar -czf "$fixtures/aegis-ssh-v0.4.0-darwin-arm64.tar.gz" "aegis-ssh-v0.4.0-darwin-arm64")
(cd "$fixtures" && shasum -a 256 "aegis-ssh-v0.4.0-darwin-arm64.tar.gz" > SHA256SUMS)

# shellcheck disable=SC2016
printf '%s\n' '#!/bin/sh' 'case "$1" in' '  -s) echo Darwin ;;' '  -m) echo arm64 ;;' 'esac' > "$fake_bin/uname"
# shellcheck disable=SC2016
printf '%s\n' '#!/bin/sh' 'case "$*" in' '  *releases/latest*) echo "{\"tag_name\":\"v0.4.0\"}" ;;' '  *SHA256SUMS*) cp "$AEGIS_FIXTURES/SHA256SUMS" "$4" ;;' '  *) cp "$AEGIS_FIXTURES/aegis-ssh-v0.4.0-darwin-arm64.tar.gz" "$4" ;;' 'esac' > "$fake_bin/curl"
# shellcheck disable=SC2016
printf '%s\n' '#!/bin/sh' 'echo called >> "$AEGIS_GO_LOG"; exit 99' > "$fake_bin/go"
chmod 0755 "$fake_bin/uname" "$fake_bin/curl" "$fake_bin/go"

export HOME="$home"
export SHELL=/bin/zsh
export AEGIS_FIXTURES="$fixtures"
export AEGIS_FAKE_LOG="$work/aegis.log"
export AEGIS_GO_LOG="$work/go.log"
export PATH="$fake_bin:/usr/bin:/bin:/usr/sbin"

(cd "$root" && "$root/scripts/install.sh")
installed_binary="$HOME/.local/bin/aegis-ssh"
expected_path_line="export PATH=\"\$HOME/.local/bin:\$PATH\""
test -x "$installed_binary"
test ! -e "$AEGIS_GO_LOG"
grep -q '^agent configure auto$' "$AEGIS_FAKE_LOG"
grep -Fqx "$expected_path_line" "$HOME/.zshrc"

printf '%s\n' '#!/bin/sh' 'exit 99' > "$work/invalid-binary"
chmod 0755 "$work/invalid-binary"
if "$root/scripts/install.sh" update --binary "$work/invalid-binary" >/dev/null 2>&1; then
    echo "invalid update unexpectedly succeeded" >&2
    exit 1
fi
test "$(grep -c '^stop$' "$AEGIS_FAKE_LOG" || true)" -eq 0
test -x "$installed_binary"

"$root/scripts/install.sh" update --version v0.4.0
test "$(grep -c '^agent configure auto$' "$AEGIS_FAKE_LOG")" -eq 2
test "$(grep -Fc "$expected_path_line" "$HOME/.zshrc")" -eq 1

mkdir -p "$HOME/.aegis-ssh"
printf 'keep\n' > "$HOME/.aegis-ssh/vault.enc"
"$root/scripts/install.sh" uninstall
test ! -e "$installed_binary"
test -f "$HOME/.aegis-ssh/vault.enc"
grep -q '^agent unconfigure auto$' "$AEGIS_FAKE_LOG"

echo "installer smoke test passed"
