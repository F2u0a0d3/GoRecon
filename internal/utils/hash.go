package utils

import (
	"crypto/sha256"
	"fmt"
)

// Hash creates a SHA256 hash of the input string
func Hash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", hash)
}

// HashBytes creates a SHA256 hash of the input bytes
func HashBytes(input []byte) string {
	hash := sha256.Sum256(input)
	return fmt.Sprintf("%x", hash)
}