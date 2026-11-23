package models

import (
	"crypto/rand"
	"encoding/hex"

	"gorm.io/gorm"
)

// keyToken describes one of the per-key server-side credentials (the stats
// token, the verify secret). Both are 128 bits of CSPRNG output behind a
// prefix, stored as a SHA-256 digest plus a short display prefix, shown once
// when issued and unrecoverable afterwards.
type keyToken struct {
	prefix     string
	hashCol    string
	displayCol string
}

// keyTokenDisplayLen is the prefix plus 8 hex characters, enough to recognise
// a token without narrowing a search. Every prefix is three characters long.
const keyTokenDisplayLen = 3 + 8

// issue generates a new token for the key, replacing any previous one, and
// returns the secret. SHA-256 is enough: 128 random bits need no slow hash.
func (t keyToken) issue(db *gorm.DB, id int64) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	secret := t.prefix + hex.EncodeToString(b)
	res := db.Model(&APIKey{}).Where(byID, id).Updates(map[string]any{
		t.hashCol:    HashMCPToken(secret),
		t.displayCol: secret[:keyTokenDisplayLen],
	})
	if res.Error != nil {
		return "", res.Error
	}
	if res.RowsAffected == 0 {
		return "", gorm.ErrRecordNotFound
	}
	return secret, nil
}

// revoke removes the key's token, if any. Existence is checked apart from the
// update: MySQL reports a write that changes nothing (a key that had no token)
// as zero rows affected, which is not a missing key.
func (t keyToken) revoke(db *gorm.DB, id int64) error {
	var n int64
	if err := db.Model(&APIKey{}).Where(byID, id).Count(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		return gorm.ErrRecordNotFound
	}
	// NULL rather than an empty string: NULLs never collide in the unique index.
	return db.Model(&APIKey{}).Where(byID, id).Updates(map[string]any{
		t.hashCol:    nil,
		t.displayCol: "",
	}).Error
}
