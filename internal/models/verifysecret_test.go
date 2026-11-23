package models_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/gatecha-org/gatecha/internal/models"
	"github.com/gatecha-org/gatecha/internal/testutil"
	"gorm.io/gorm"
)

func TestVerifySecret_IssueMatchRevoke(t *testing.T) {
	db := testutil.SetupTestDB(t)
	key, _ := models.CreateAPIKey(db, "k", "", 0, 0, "")
	other, _ := models.CreateAPIKey(db, "other", "", 0, 0, "")

	secret, err := models.IssueVerifySecret(db, key.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, models.VerifySecretPrefix) || len(secret) != 3+32 {
		t.Fatalf("unexpected secret shape %q", secret)
	}

	loaded, _ := models.GetAPIKeyByID(db, key.ID)
	if !loaded.MatchesVerifySecret(secret) {
		t.Error("issued secret does not match")
	}
	if loaded.VerifySecretDisplay != secret[:11] {
		t.Errorf("display = %q, want %q", loaded.VerifySecretDisplay, secret[:11])
	}
	if *loaded.VerifySecretHash == secret {
		t.Error("secret stored in clear")
	}
	for _, wrong := range []string{"", secret[:len(secret)-1], models.StatsTokenPrefix + secret[3:], strings.ToUpper(secret)} {
		if loaded.MatchesVerifySecret(wrong) {
			t.Errorf("%q matched", wrong)
		}
	}
	otherLoaded, _ := models.GetAPIKeyByID(db, other.ID)
	if otherLoaded.HasVerifySecret() || otherLoaded.MatchesVerifySecret(secret) {
		t.Error("another key accepts this secret")
	}

	if err := models.RevokeVerifySecret(db, key.ID); err != nil {
		t.Fatal(err)
	}
	loaded, _ = models.GetAPIKeyByID(db, key.ID)
	if loaded.HasVerifySecret() || loaded.MatchesVerifySecret(secret) || loaded.VerifySecretDisplay != "" {
		t.Error("revoked secret still present")
	}
	// Revoking again is not an error, even though no row changes.
	if err := models.RevokeVerifySecret(db, key.ID); err != nil {
		t.Errorf("second revoke: %v", err)
	}
}

func TestVerifySecret_MissingKey(t *testing.T) {
	db := testutil.SetupTestDB(t)
	if _, err := models.IssueVerifySecret(db, 999); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("issue on missing key: got %v", err)
	}
	if err := models.RevokeVerifySecret(db, 999); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("revoke on missing key: got %v", err)
	}
}

// The verify secret and the stats token are separate credentials: issuing
// one leaves the other alone.
func TestVerifySecret_IndependentOfStatsToken(t *testing.T) {
	db := testutil.SetupTestDB(t)
	key, _ := models.CreateAPIKey(db, "k", "", 0, 0, "")
	token, _ := models.IssueStatsToken(db, key.ID)
	secret, _ := models.IssueVerifySecret(db, key.ID)

	if found, err := models.GetAPIKeyByStatsToken(db, token); err != nil || found.ID != key.ID {
		t.Errorf("stats token lost after issuing a verify secret: %v", err)
	}
	_ = models.RevokeStatsToken(db, key.ID)
	loaded, _ := models.GetAPIKeyByID(db, key.ID)
	if !loaded.MatchesVerifySecret(secret) {
		t.Error("verify secret lost after revoking the stats token")
	}
}
