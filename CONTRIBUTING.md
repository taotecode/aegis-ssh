# Contributing to Aegis SSH

Contributions are welcome when they keep credentials local, preserve the standard MCP boundary, and solve a concrete user workflow.

## Before opening an issue

- Search existing issues first.
- Use the Bug report form for reproducible failures and the Feature request form for proposals.
- Remove credentials, hosts, addresses, private aliases, recovery material, vault files, and raw audit data.
- Follow [SECURITY.md](SECURITY.md) for security-sensitive reports.

## Development

Requirements:

- Go 1.25 or newer;
- POSIX shell for installer work;
- `shellcheck` for shell changes.

Run the relevant checks before submitting:

```bash
gofmt -w <changed-go-files>
go test ./...
go test -race ./...
go vet ./...
sh -n scripts/install.sh scripts/install_test.sh
shellcheck scripts/install.sh scripts/install_test.sh
scripts/install_test.sh
```

For packaging changes, also run:

```bash
scripts/package.sh /tmp/aegis-ssh-dist
```

## Pull requests

- Keep each pull request focused on one problem.
- Reuse existing patterns and the Go standard library before adding dependencies or abstractions.
- Add the smallest test that would fail without the change.
- Update both English and Simplified Chinese documentation for user-facing behavior.
- Explain compatibility, migration, and security effects when they exist.
- Do not commit generated release archives, local configuration, credentials, or private infrastructure data.
