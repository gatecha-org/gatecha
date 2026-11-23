package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gatecha-org/gatecha/internal/models"
	"github.com/gatecha-org/gatecha/internal/testutil"
	"gorm.io/gorm"
)

const (
	backendIP  = "192.0.2.10"
	verifyPath = "/api/v1/verify?apiKey="
)

func issueVerifySecret(t *testing.T, router http.Handler, keyID int64) string {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/admin/keys/"+strconv.FormatInt(keyID, 10)+"/verify-secret", nil)
	req.Header.Set("Authorization", bearerPrefix+getAdminToken(t))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("issue verify secret: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if !strings.HasPrefix(resp["verify_secret"], models.VerifySecretPrefix) {
		t.Fatalf("expected a gv_ secret, got %q", resp["verify_secret"])
	}
	return resp["verify_secret"]
}

// verifyFromBackend posts to /verify from backendIP, as a site backend does.
func verifyFromBackend(router http.Handler, keyID, secret, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", verifyPath+keyID, strings.NewReader(body))
	req.RemoteAddr = backendIP + ":1234"
	if secret != "" {
		req.Header.Set("Authorization", bearerPrefix+secret)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func clientIPBody(ip string) string {
	return `{"payload":"x","client_ip":"` + ip + `"}`
}

// The point of #212: with the verify secret, each visitor gets the budget, so
// a site past the limit no longer throttles all its visitors at once.
func TestVerifySecret_RateLimitsPerVisitor(t *testing.T) {
	db := testutil.SetupTestDB(t)
	key, _ := models.CreateAPIKey(db, "site", "", 0, 0, "")
	router := NewRouter(db, testSecretKey, RouterConfig{RateLimitEnabled: true, RateLimitAPI: 2, RateLimitLogin: 5})
	secret := issueVerifySecret(t, router, key.ID)

	for i := range 2 {
		if w := verifyFromBackend(router, key.KeyID, secret, clientIPBody("203.0.113.1")); w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d throttled within budget", i+1)
		}
	}
	if w := verifyFromBackend(router, key.KeyID, secret, clientIPBody("203.0.113.1")); w.Code != http.StatusTooManyRequests {
		t.Errorf("visitor over budget: expected 429, got %d", w.Code)
	}
	// Same backend, another visitor: a fresh bucket.
	if w := verifyFromBackend(router, key.KeyID, secret, clientIPBody("203.0.113.2")); w.Code == http.StatusTooManyRequests {
		t.Error("second visitor throttled by the first one's budget")
	}
	// The two spellings of one IPv4 visitor share a bucket.
	if w := verifyFromBackend(router, key.KeyID, secret, clientIPBody("::ffff:203.0.113.1")); w.Code != http.StatusTooManyRequests {
		t.Errorf("IPv4-mapped spelling escaped the visitor's bucket: got %d", w.Code)
	}
}

// Without the secret, client_ip is only a claim from someone holding a public
// key ID, and must change nothing.
func TestVerifySecret_ClientIPIgnoredWithoutSecret(t *testing.T) {
	db := testutil.SetupTestDB(t)
	key, _ := models.CreateAPIKey(db, "site", "", 0, 0, "")
	router := NewRouter(db, testSecretKey, RouterConfig{RateLimitEnabled: true, RateLimitAPI: 2, RateLimitLogin: 5})
	issueVerifySecret(t, router, key.ID)

	for i := range 2 {
		verifyFromBackend(router, key.KeyID, "", clientIPBody("203.0.113."+strconv.Itoa(i+1)))
	}
	if w := verifyFromBackend(router, key.KeyID, "", clientIPBody("203.0.113.9")); w.Code != http.StatusTooManyRequests {
		t.Errorf("rotating client_ip without the secret walked around the limit: got %d", w.Code)
	}
}

// A valid secret with an unusable client_ip falls back to the connecting
// address instead of failing the verification.
func TestVerifySecret_InvalidClientIPFallsBack(t *testing.T) {
	db := testutil.SetupTestDB(t)
	key, _ := models.CreateAPIKey(db, "site", "", 0, 0, "")
	router := NewRouter(db, testSecretKey, RouterConfig{RateLimitEnabled: true, RateLimitAPI: 2, RateLimitLogin: 5})
	secret := issueVerifySecret(t, router, key.ID)

	bodies := []string{clientIPBody("not-an-ip"), `{"payload":"x"}`}
	for _, body := range bodies {
		if w := verifyFromBackend(router, key.KeyID, secret, body); w.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d: %s", body, w.Code, w.Body.String())
		}
	}
	// Both drew on the backend's own bucket, now empty.
	if w := verifyFromBackend(router, key.KeyID, secret, clientIPBody("bogus")); w.Code != http.StatusTooManyRequests {
		t.Errorf("unusable client_ip did not count against the backend: got %d", w.Code)
	}
}

// The body read by the middleware must still reach the handler intact.
func TestVerifySecret_BodyStillReachesHandler(t *testing.T) {
	router, db := setupTestRouter(t)
	key, _ := models.CreateAPIKey(db, "site", "", 0, 0, "")
	secret := issueVerifySecret(t, router, key.ID)

	w := verifyFromBackend(router, key.KeyID, secret, `{"client_ip":"203.0.113.1"}`)
	if !strings.Contains(w.Body.String(), "missing payload") {
		t.Errorf("handler did not see the body: %d %s", w.Code, w.Body.String())
	}
	// A client_ip of the wrong type is ignored, with or without the secret,
	// never a reason to reject the verification.
	for _, sec := range []string{secret, ""} {
		w = verifyFromBackend(router, key.KeyID, sec, `{"payload":"x","client_ip":42}`)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "invalid payload") {
			t.Errorf("non-string client_ip (secret %v): expected the payload to be checked, got %d %s", sec != "", w.Code, w.Body.String())
		}
	}
	w = verifyFromBackend(router, key.KeyID, secret, `not json`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("malformed body: expected 400 from the handler, got %d", w.Code)
	}
}

// The reported address, not the backend's, feeds the country breakdown.
func TestVerifySecret_CountryFromClientIP(t *testing.T) {
	router, db := setupTestRouter(t)
	key, _ := models.CreateAPIKey(db, "site", "", 0, 0, "")
	secret := issueVerifySecret(t, router, key.ID)

	// A payload that is not base64 fails after the country is resolved.
	verifyFromBackend(router, key.KeyID, secret, `{"payload":"!!!","client_ip":"8.8.8.8"}`)

	stats, err := models.GetCountryStats(db, &key.ID, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 1 || len(stats[0].Country) != 2 || stats[0].Country == "unknown" {
		t.Fatalf("expected one public country from client_ip, got %+v", stats)
	}
}

// A secret that does not match is ignored, not refused: the verification goes
// through and client_ip is not trusted, so the backend's own bucket applies.
// Refusing would make every rotation an outage for the site.
func TestVerifySecret_WrongSecretIgnored(t *testing.T) {
	cases := map[string]func(t *testing.T, router http.Handler, other int64) string{
		"another key's secret": func(t *testing.T, router http.Handler, other int64) string {
			return issueVerifySecret(t, router, other)
		},
		"made-up secret": func(*testing.T, http.Handler, int64) string {
			return models.VerifySecretPrefix + strings.Repeat("0", 32)
		},
		"truncated secret": func(*testing.T, http.Handler, int64) string { return models.VerifySecretPrefix + "abc" },
	}
	for name, makeSecret := range cases {
		t.Run(name, func(t *testing.T) {
			db := testutil.SetupTestDB(t)
			a, _ := models.CreateAPIKey(db, "a", "", 0, 0, "")
			b, _ := models.CreateAPIKey(db, "b", "", 0, 0, "")
			router := NewRouter(db, testSecretKey, RouterConfig{RateLimitEnabled: true, RateLimitAPI: 2, RateLimitLogin: 5})
			secret := makeSecret(t, router, b.ID)
			for i := range 2 {
				if w := verifyFromBackend(router, a.KeyID, secret, clientIPBody("203.0.113."+strconv.Itoa(i+1))); w.Code != http.StatusOK {
					t.Fatalf("request %d: expected 200, got %d", i+1, w.Code)
				}
			}
			if w := verifyFromBackend(router, a.KeyID, secret, clientIPBody("203.0.113.9")); w.Code != http.StatusTooManyRequests {
				t.Errorf("client_ip trusted on a wrong secret: got %d", w.Code)
			}
		})
	}
}

func TestVerifySecret_ReissueAndRevoke(t *testing.T) {
	router, db := setupTestRouter(t)
	key, _ := models.CreateAPIKey(db, "site", "", 0, 0, "")
	old := issueVerifySecret(t, router, key.ID)
	current := issueVerifySecret(t, router, key.ID)

	if !trusted(t, db, key.ID, func(body string) { verifyFromBackend(router, key.KeyID, current, body) }) {
		t.Error("current secret: client_ip not trusted")
	}
	if trusted(t, db, key.ID, func(body string) { verifyFromBackend(router, key.KeyID, old, body) }) {
		t.Error("replaced secret: client_ip still trusted")
	}

	req := httptest.NewRequest("DELETE", "/api/admin/keys/"+strconv.FormatInt(key.ID, 10)+"/verify-secret", nil)
	req.Header.Set("Authorization", bearerPrefix+getAdminToken(t))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("revoke: expected 204, got %d", w.Code)
	}
	if trusted(t, db, key.ID, func(body string) { verifyFromBackend(router, key.KeyID, current, body) }) {
		t.Error("revoked secret: client_ip still trusted")
	}
	// The site keeps verifying with its stale secret: no outage.
	if w := verifyFromBackend(router, key.KeyID, current, `{"payload":"x"}`); w.Code != http.StatusOK {
		t.Errorf("verify with a revoked secret: expected 200, got %d", w.Code)
	}
}

// trusted reports whether send's client_ip was honoured, by sending a public
// address and checking it reached the country breakdown. The connecting
// address in these tests is a documentation range that resolves to "unknown".
func trusted(t *testing.T, db *gorm.DB, apiKeyID int64, send func(body string)) bool {
	t.Helper()
	if err := db.Where("api_key_id = ?", apiKeyID).Delete(&models.DailyCountryStat{}).Error; err != nil {
		t.Fatal(err)
	}
	send(`{"payload":"!!!","client_ip":"8.8.8.8"}`)
	stats, err := models.GetCountryStats(db, &apiKeyID, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	return len(stats) == 1 && len(stats[0].Country) == 2
}

func TestVerifySecret_AdminErrors(t *testing.T) {
	router, _ := setupTestRouter(t)
	for _, method := range []string{"POST", "DELETE"} {
		for path, want := range map[string]int{
			"/api/admin/keys/999/verify-secret": http.StatusNotFound,
			"/api/admin/keys/abc/verify-secret": http.StatusBadRequest,
		} {
			req := httptest.NewRequest(method, path, nil)
			req.Header.Set("Authorization", bearerPrefix+getAdminToken(t))
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != want {
				t.Errorf("%s %s: expected %d, got %d", method, path, want, w.Code)
			}
		}
		req := httptest.NewRequest(method, "/api/admin/keys/1/verify-secret", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s without auth: expected 401, got %d", method, w.Code)
		}
	}
}

func TestVerifySecret_ShownInKeyButNeverItsHash(t *testing.T) {
	router, db := setupTestRouter(t)
	key, _ := models.CreateAPIKey(db, "k", "", 0, 0, "")
	secret := issueVerifySecret(t, router, key.ID)
	hash := models.HashMCPToken(secret)

	for _, path := range []string{"/api/admin/keys", "/api/admin/keys/" + strconv.FormatInt(key.ID, 10)} {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", bearerPrefix+getAdminToken(t))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		body := w.Body.String()
		if strings.Contains(body, hash) || strings.Contains(body, secret) {
			t.Errorf("%s leaks the verify secret or its hash", path)
		}
		if !strings.Contains(body, `"verify_secret_display":"`+secret[:11]+`"`) {
			t.Errorf("%s should show the secret's display prefix %q", path, secret[:11])
		}
	}
}

func TestParseClientIP(t *testing.T) {
	for body, want := range map[string]string{
		`{"client_ip":"203.0.113.7"}`:        "203.0.113.7",
		`{"client_ip":" 203.0.113.7 "}`:      "203.0.113.7",
		`{"client_ip":"::ffff:203.0.113.7"}`: "203.0.113.7",
		`{"client_ip":"2001:DB8::1"}`:        "2001:db8::1",
		`{"client_ip":"fe80::1%eth0"}`:       "fe80::1",
		`{"client_ip":"203.0.113.7:443"}`:    "",
		`{"client_ip":"example.com"}`:        "",
		`{"client_ip":42}`:                   "",
		`{}`:                                 "",
		`not json`:                           "",
	} {
		if got := parseClientIP([]byte(body)); got != want {
			t.Errorf("parseClientIP(%s) = %q, want %q", body, got, want)
		}
	}
}
