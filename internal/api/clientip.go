package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"

	"github.com/gatecha-org/gatecha/internal/models"
)

const trustedClientIPContextKey contextKey = "trusted_client_ip"

// TrustedClientIPMiddleware lets a site backend report the visitor's address
// on POST /verify. A server-side caller is otherwise seen as itself, so every
// visitor of a site shared one rate-limit bucket and resolved to the hosting
// provider's country.
//
// The `client_ip` body field is honoured only alongside the key's verify
// secret, sent as `Authorization: Bearer gv_…` (the key ID then travels in
// `?apiKey=`). The key ID is public, so without a secret anyone could rotate
// `client_ip` on every request and walk around the limiter. Without the
// header the field is ignored and nothing changes.
//
// A wrong, replaced or revoked secret is ignored the same way, with a warning
// in the logs, rather than refused. Refusing would turn a secret rotation into
// an outage: every form of the site would fail verification until its backend
// was updated. Ignoring it costs at most the shared bucket the site had before,
// and grants nothing, since the address is simply not trusted.
//
// The address replaces the connecting one for the per-source rate limit and
// the country lookup, and nothing else: it is never stored nor logged. A value
// that does not parse as an IP address is ignored.
//
// It must run after APIKeyMiddleware and before the limiter it feeds.
func TrustedClientIPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret, ok := strings.CutPrefix(r.Header.Get("Authorization"), bearerPrefix)
		if !ok || !strings.HasPrefix(secret, models.VerifySecretPrefix) {
			next.ServeHTTP(w, r)
			return
		}
		key := GetAPIKeyFromContext(r)
		if key == nil || !key.MatchesVerifySecret(secret) {
			if key != nil {
				slog.Warn("verify secret does not match this key, client_ip ignored", "key_id", key.KeyID)
			}
			next.ServeHTTP(w, r)
			return
		}

		// Read the body here and hand an identical copy downstream. Its size
		// is already capped by MaxBodyBytesMiddleware.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, verifyResponse{OK: false, Error: "invalid request body"})
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		if ip := parseClientIP(body); ip != "" {
			r = r.WithContext(context.WithValue(r.Context(), trustedClientIPContextKey, ip))
		} else {
			slog.Debug("verify secret without a usable client_ip, using the connecting address", "key_id", key.KeyID)
		}
		next.ServeHTTP(w, r)
	})
}

// parseClientIP returns the canonical form of the body's `client_ip`, or ""
// when it is absent or not an IP address. An IPv4-mapped IPv6 address is
// unmapped so that both spellings of one visitor share a bucket. A malformed
// body is left for the handler to reject.
func parseClientIP(body []byte) string {
	var req struct {
		ClientIP string `json:"client_ip"`
	}
	if json.Unmarshal(body, &req) != nil || req.ClientIP == "" {
		return ""
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(req.ClientIP))
	if err != nil {
		return ""
	}
	return addr.Unmap().WithZone("").String()
}

// sourceIP is the address a request is attributed to: the visitor's, when a
// trusted backend reported it, otherwise the connecting peer's.
func sourceIP(r *http.Request) string {
	if ip, ok := r.Context().Value(trustedClientIPContextKey).(string); ok && ip != "" {
		return ip
	}
	return clientIP(r)
}
