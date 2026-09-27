package ingestion

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Fingerprint is what makes a broken rule produce ONE incident instead of
// fifty thousand.
//
// The algorithm is ported byte for byte from the Python clusterer that ran
// against this laboratory, and it has to stay that way: the incidents
// imported from the old console carry its output as their fingerprint, and a
// different function would make every one of them look new.
//
//	sha256("rule|host|entity_kind|entity")[:16]
//
// Sixteen hex characters — eight bytes. Short enough to read in a log line,
// wide enough that a collision between two real rules is not a concern at
// this scale.
func Fingerprint(rule, host, entityKind, entity string) []byte {
	material := fmt.Sprintf("%s|%s|%s|%s", rule, host, entityKind, entity)
	sum := sha256.Sum256([]byte(material))
	hexed := hex.EncodeToString(sum[:])[:16]
	out, _ := hex.DecodeString(hexed)
	return out
}

func FingerprintHex(rule, host, entityKind, entity string) string {
	return hex.EncodeToString(Fingerprint(rule, host, entityKind, entity))
}
