package skills

import "embed"

// FS keeps the public Skill available to standalone release binaries.
//
//go:embed all:aegis-ssh
var FS embed.FS
