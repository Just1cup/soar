// Package migrations embeds the SQL files so the deployed artefact is a single
// binary. A migration that ships beside the image instead of inside it is a
// migration that can be the wrong version.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
