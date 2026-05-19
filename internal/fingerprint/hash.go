package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
)

// sha256Trunc returns the first `n` hex chars of sha256(s). Used by JA4
// for the truncated cipher and extension hashes.
func sha256Trunc(s string, n int) string {
	if s == "" {
		// JA4 spec: empty list hashes to "000000000000".
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	full := hex.EncodeToString(sum[:])
	if n > len(full) {
		return full
	}
	return full[:n]
}
