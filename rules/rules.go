// Package rules embeds the default detection rules into the proctrace binary,
// so the agent does not depend on a rule file that someone could edit or
// delete. Print them with "proctrace -dump-rules" to start a custom set.
package rules

import _ "embed"

// Default is the content of default.json, compiled into the binary.
//
//go:embed default.json
var Default []byte