## Summary

<!-- What changed and why? Keep this focused on one problem. -->

Closes #

## Verification

<!-- List the exact commands or manual checks performed. -->

```text
go test ./...
```

## Checklist

- [ ] The change is scoped to the stated problem and preserves existing CLI/MCP contracts.
- [ ] Tests cover non-trivial behavior and `go test ./...` passes.
- [ ] `go test -race ./...` and `go vet ./...` pass for Go changes.
- [ ] Shell changes pass `sh -n` and `shellcheck`.
- [ ] User-facing behavior is documented in English and Simplified Chinese where applicable.
- [ ] No credentials, hosts, addresses, vault data, recovery material, or private logs are included.
