package models

import (
	"crypto/subtle"
	"strings"

	"gorm.io/gorm"
)

// VerifySecretPrefix marks a per-key server-side verify secret, distinct from
// the public gk_ key ID, the gs_ stats token and the gm_ MCP tokens.
const VerifySecretPrefix = "gv_"

// verifySecret is the verify secret's storage.
var verifySecret = keyToken{prefix: VerifySecretPrefix, hashCol: "verify_secret_hash", displayCol: "verify_secret_display"}

// IssueVerifySecret generates a new verify secret for the key, replacing any
// previous one, and returns it. It is shown once and unrecoverable afterwards.
func IssueVerifySecret(db *gorm.DB, id int64) (string, error) {
	return verifySecret.issue(db, id)
}

// RevokeVerifySecret removes the key's verify secret, if any. Backends that
// still send it are then refused until they are given a new one.
func RevokeVerifySecret(db *gorm.DB, id int64) error {
	return verifySecret.revoke(db, id)
}

// HasVerifySecret reports whether a verify secret is issued for this key.
func (k *APIKey) HasVerifySecret() bool {
	return k.VerifySecretHash != nil && *k.VerifySecretHash != ""
}

// MatchesVerifySecret reports whether secret is this key's verify secret. The
// digests are compared in constant time.
func (k *APIKey) MatchesVerifySecret(secret string) bool {
	if !k.HasVerifySecret() || !strings.HasPrefix(secret, VerifySecretPrefix) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(HashMCPToken(secret)), []byte(*k.VerifySecretHash)) == 1
}
