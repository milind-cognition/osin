package example

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openshift/osin"
)

// newIntrospectHandler builds the same introspection handler used in the
// example servers (complete.go / simple.go) so we can test it in isolation.
func newIntrospectHandler(server *osin.Server, cfg *osin.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]interface{}{"active": false})
			return
		}

		r.ParseForm()
		token := r.FormValue("token")
		if token == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":             "invalid_request",
				"error_description": "token parameter is required",
			})
			return
		}

		tokenTypeHint := r.FormValue("token_type_hint")

		var accessData *osin.AccessData
		storage := server.Storage.Clone()
		defer storage.Close()

		switch tokenTypeHint {
		case "refresh_token":
			if ad, err := storage.LoadRefresh(token); err == nil && ad != nil {
				accessData = ad
			} else if ad, err := storage.LoadAccess(token); err == nil && ad != nil {
				accessData = ad
			}
		default:
			if ad, err := storage.LoadAccess(token); err == nil && ad != nil {
				accessData = ad
			} else if ad, err := storage.LoadRefresh(token); err == nil && ad != nil {
				accessData = ad
			}
		}

		if accessData == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"active": false})
			return
		}

		response := map[string]interface{}{
			"active":     !accessData.IsExpired(),
			"client_id":  accessData.Client.GetId(),
			"token_type": cfg.TokenType,
			"exp":        accessData.CreatedAt.Add(time.Duration(accessData.ExpiresIn) * time.Second).Unix(),
			"iat":        accessData.CreatedAt.Unix(),
		}

		if accessData.Scope != "" {
			response["scope"] = accessData.Scope
		}

		json.NewEncoder(w).Encode(response)
	}
}

// setupTestServer creates an osin.Server with pre-populated storage for tests.
// Returns the server, config, and storage so tests can add/inspect data.
func setupTestServer() (*osin.Server, *osin.ServerConfig, *TestStorage) {
	cfg := osin.NewServerConfig()
	cfg.AllowedAccessTypes = osin.AllowedAccessType{
		osin.AUTHORIZATION_CODE, osin.REFRESH_TOKEN,
	}
	storage := NewTestStorage()
	server := osin.NewServer(cfg, storage)
	return server, cfg, storage
}

// seedAccessToken stores a valid access token in the test storage.
func seedAccessToken(storage *TestStorage, token string, clientID string, expiresIn int32, scope string, createdAt time.Time) {
	client, _ := storage.GetClient(clientID)
	ad := &osin.AccessData{
		Client:      client,
		AccessToken: token,
		ExpiresIn:   expiresIn,
		Scope:       scope,
		CreatedAt:   createdAt,
	}
	storage.SaveAccess(ad)
}

// seedRefreshToken stores an access+refresh token pair in the test storage.
func seedRefreshToken(storage *TestStorage, accessToken string, refreshToken string, clientID string, expiresIn int32, scope string, createdAt time.Time) {
	client, _ := storage.GetClient(clientID)
	ad := &osin.AccessData{
		Client:       client,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
		Scope:        scope,
		CreatedAt:    createdAt,
	}
	storage.SaveAccess(ad)
}

func postIntrospect(handler http.Handler, formValues url.Values) *httptest.ResponseRecorder {
	body := formValues.Encode()
	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func decodeJSON(t *testing.T, rr *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var result map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}
	return result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestIntrospectRejectsGetMethod(t *testing.T) {
	server, cfg, _ := setupTestServer()
	handler := newIntrospectHandler(server, cfg)

	req := httptest.NewRequest("GET", "/introspect?token=foo", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}

	result := decodeJSON(t, rr)
	if active, ok := result["active"].(bool); !ok || active {
		t.Fatalf("Expected active=false, got %v", result["active"])
	}
}

func TestIntrospectRejectsMissingToken(t *testing.T) {
	server, cfg, _ := setupTestServer()
	handler := newIntrospectHandler(server, cfg)

	// POST with no token parameter
	rr := postIntrospect(handler, url.Values{})

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}

	result := decodeJSON(t, rr)
	if result["error"] != "invalid_request" {
		t.Fatalf("Expected error=invalid_request, got %v", result["error"])
	}
	if result["error_description"] != "token parameter is required" {
		t.Fatalf("Expected error_description about token being required, got %v", result["error_description"])
	}
}

func TestIntrospectUnknownTokenReturnsInactive(t *testing.T) {
	server, cfg, _ := setupTestServer()
	handler := newIntrospectHandler(server, cfg)

	rr := postIntrospect(handler, url.Values{"token": {"nonexistent-token"}})

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", rr.Code)
	}

	result := decodeJSON(t, rr)
	if active, ok := result["active"].(bool); !ok || active {
		t.Fatalf("Expected active=false for unknown token, got %v", result["active"])
	}
}

func TestIntrospectValidAccessToken(t *testing.T) {
	server, cfg, storage := setupTestServer()
	handler := newIntrospectHandler(server, cfg)

	now := time.Now()
	seedAccessToken(storage, "valid-access-token", "1234", 3600, "read write", now)

	rr := postIntrospect(handler, url.Values{"token": {"valid-access-token"}})

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", rr.Code)
	}

	result := decodeJSON(t, rr)

	if active, ok := result["active"].(bool); !ok || !active {
		t.Fatalf("Expected active=true, got %v", result["active"])
	}
	if result["client_id"] != "1234" {
		t.Fatalf("Expected client_id=1234, got %v", result["client_id"])
	}
	if result["token_type"] != "Bearer" {
		t.Fatalf("Expected token_type=Bearer, got %v", result["token_type"])
	}
	if result["scope"] != "read write" {
		t.Fatalf("Expected scope='read write', got %v", result["scope"])
	}

	// Verify exp and iat are present and numeric
	expVal, ok := result["exp"].(float64)
	if !ok {
		t.Fatalf("Expected exp to be a number, got %T", result["exp"])
	}
	expectedExp := now.Add(3600 * time.Second).Unix()
	if int64(expVal) != expectedExp {
		t.Fatalf("Expected exp=%d, got %d", expectedExp, int64(expVal))
	}

	iatVal, ok := result["iat"].(float64)
	if !ok {
		t.Fatalf("Expected iat to be a number, got %T", result["iat"])
	}
	if int64(iatVal) != now.Unix() {
		t.Fatalf("Expected iat=%d, got %d", now.Unix(), int64(iatVal))
	}
}

func TestIntrospectExpiredTokenReturnsInactive(t *testing.T) {
	server, cfg, storage := setupTestServer()
	handler := newIntrospectHandler(server, cfg)

	// Created 2 hours ago with 1 hour expiry -> expired
	expired := time.Now().Add(-2 * time.Hour)
	seedAccessToken(storage, "expired-token", "1234", 3600, "", expired)

	rr := postIntrospect(handler, url.Values{"token": {"expired-token"}})

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", rr.Code)
	}

	result := decodeJSON(t, rr)
	if active, ok := result["active"].(bool); !ok || active {
		t.Fatalf("Expected active=false for expired token, got %v", result["active"])
	}
	// Even expired tokens should return metadata
	if result["client_id"] != "1234" {
		t.Fatalf("Expected client_id=1234 even for expired token, got %v", result["client_id"])
	}
}

func TestIntrospectTokenWithNoScope(t *testing.T) {
	server, cfg, storage := setupTestServer()
	handler := newIntrospectHandler(server, cfg)

	now := time.Now()
	seedAccessToken(storage, "no-scope-token", "1234", 3600, "", now)

	rr := postIntrospect(handler, url.Values{"token": {"no-scope-token"}})

	result := decodeJSON(t, rr)

	if active, ok := result["active"].(bool); !ok || !active {
		t.Fatalf("Expected active=true, got %v", result["active"])
	}
	// scope field should be omitted when empty
	if _, exists := result["scope"]; exists {
		t.Fatalf("Expected scope to be absent, got %v", result["scope"])
	}
}

func TestIntrospectRefreshToken(t *testing.T) {
	server, cfg, storage := setupTestServer()
	handler := newIntrospectHandler(server, cfg)

	now := time.Now()
	seedRefreshToken(storage, "access-for-refresh", "my-refresh-token", "1234", 3600, "admin", now)

	// Look up by refresh token with the correct hint
	rr := postIntrospect(handler, url.Values{
		"token":           {"my-refresh-token"},
		"token_type_hint": {"refresh_token"},
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", rr.Code)
	}

	result := decodeJSON(t, rr)
	if active, ok := result["active"].(bool); !ok || !active {
		t.Fatalf("Expected active=true, got %v", result["active"])
	}
	if result["client_id"] != "1234" {
		t.Fatalf("Expected client_id=1234, got %v", result["client_id"])
	}
	if result["scope"] != "admin" {
		t.Fatalf("Expected scope=admin, got %v", result["scope"])
	}
}

func TestIntrospectRefreshTokenWithoutHint(t *testing.T) {
	server, cfg, storage := setupTestServer()
	handler := newIntrospectHandler(server, cfg)

	now := time.Now()
	seedRefreshToken(storage, "access-for-refresh2", "refresh-no-hint", "1234", 3600, "read", now)

	// Default hint (no token_type_hint) should still find refresh tokens
	// after failing to find an access token with that value
	rr := postIntrospect(handler, url.Values{"token": {"refresh-no-hint"}})

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", rr.Code)
	}

	result := decodeJSON(t, rr)
	if active, ok := result["active"].(bool); !ok || !active {
		t.Fatalf("Expected active=true for refresh token looked up without hint, got %v", result["active"])
	}
}

func TestIntrospectAccessTokenWithRefreshHint(t *testing.T) {
	server, cfg, storage := setupTestServer()
	handler := newIntrospectHandler(server, cfg)

	now := time.Now()
	seedAccessToken(storage, "access-only-token", "1234", 3600, "", now)

	// Using refresh_token hint but providing an access token value.
	// The handler should fall back to checking access tokens.
	rr := postIntrospect(handler, url.Values{
		"token":           {"access-only-token"},
		"token_type_hint": {"refresh_token"},
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", rr.Code)
	}

	result := decodeJSON(t, rr)
	if active, ok := result["active"].(bool); !ok || !active {
		t.Fatalf("Expected active=true with mismatched hint, got %v", result["active"])
	}
}

func TestIntrospectResponseContentType(t *testing.T) {
	server, cfg, _ := setupTestServer()
	handler := newIntrospectHandler(server, cfg)

	rr := postIntrospect(handler, url.Values{"token": {"anything"}})

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("Expected Content-Type=application/json, got %s", ct)
	}
}

func TestIntrospectRejectsPutMethod(t *testing.T) {
	server, cfg, _ := setupTestServer()
	handler := newIntrospectHandler(server, cfg)

	req := httptest.NewRequest("PUT", "/introspect", strings.NewReader("token=foo"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("Expected status %d for PUT, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestIntrospectEmptyTokenParameter(t *testing.T) {
	server, cfg, _ := setupTestServer()
	handler := newIntrospectHandler(server, cfg)

	// Explicitly send token="" (empty string)
	rr := postIntrospect(handler, url.Values{"token": {""}})

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Expected status %d for empty token, got %d", http.StatusBadRequest, rr.Code)
	}

	result := decodeJSON(t, rr)
	if result["error"] != "invalid_request" {
		t.Fatalf("Expected error=invalid_request, got %v", result["error"])
	}
}
