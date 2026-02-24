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

// buildIntrospectHandler creates an introspection handler identical to the one
// added in the example servers (complete.go / simple.go). This allows us to
// unit-test the handler logic without starting a real HTTP server.
func buildIntrospectHandler(server *osin.Server, cfg *osin.ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// RFC 7662 requires POST method
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

		// Try to load the token from storage
		var accessData *osin.AccessData
		storage := server.Storage.Clone()
		defer storage.Close()

		switch tokenTypeHint {
		case "refresh_token":
			// Try refresh token first, then access token
			if ad, err := storage.LoadRefresh(token); err == nil && ad != nil {
				accessData = ad
			} else if ad, err := storage.LoadAccess(token); err == nil && ad != nil {
				accessData = ad
			}
		default:
			// Try access token first, then refresh token
			if ad, err := storage.LoadAccess(token); err == nil && ad != nil {
				accessData = ad
			} else if ad, err := storage.LoadRefresh(token); err == nil && ad != nil {
				accessData = ad
			}
		}

		// Token not found - return inactive per RFC 7662 Section 2.2
		if accessData == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"active": false})
			return
		}

		// Build RFC 7662 compliant response
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

// setupTestServer creates an osin.Server with a TestStorage pre-populated
// with known tokens for testing.
func setupTestServer() (*osin.Server, *osin.ServerConfig, *TestStorage) {
	cfg := osin.NewServerConfig()
	cfg.AllowedAccessTypes = osin.AllowedAccessType{osin.AUTHORIZATION_CODE, osin.REFRESH_TOKEN}
	storage := NewTestStorage()

	client := &osin.DefaultClient{
		Id:          "test-client",
		Secret:      "test-secret",
		RedirectUri: "http://localhost:14000/appauth",
	}
	storage.SetClient("test-client", client)

	now := time.Now()

	// Store a valid (non-expired) access token
	validAccess := &osin.AccessData{
		Client:      client,
		AccessToken: "valid-access-token",
		ExpiresIn:   3600,
		CreatedAt:   now,
		Scope:       "read write",
	}
	storage.SaveAccess(validAccess)

	// Store a valid access token without scope
	noScopeAccess := &osin.AccessData{
		Client:      client,
		AccessToken: "no-scope-token",
		ExpiresIn:   3600,
		CreatedAt:   now,
	}
	storage.SaveAccess(noScopeAccess)

	// Store an expired access token
	expiredAccess := &osin.AccessData{
		Client:      client,
		AccessToken: "expired-token",
		ExpiresIn:   1,
		CreatedAt:   now.Add(-2 * time.Hour),
	}
	storage.SaveAccess(expiredAccess)

	// Store an access token with a refresh token
	refreshableAccess := &osin.AccessData{
		Client:       client,
		AccessToken:  "refreshable-access-token",
		RefreshToken: "valid-refresh-token",
		ExpiresIn:    3600,
		CreatedAt:    now,
		Scope:        "admin",
	}
	storage.SaveAccess(refreshableAccess)

	server := osin.NewServer(cfg, storage)
	return server, cfg, storage
}

func TestIntrospectGetMethodReturns405(t *testing.T) {
	server, cfg, _ := setupTestServer()
	handler := buildIntrospectHandler(server, cfg)

	req := httptest.NewRequest("GET", "/introspect", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %s", ct)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}
	if active, ok := body["active"].(bool); !ok || active {
		t.Fatalf("expected active=false, got %v", body["active"])
	}
}

func TestIntrospectPutMethodReturns405(t *testing.T) {
	server, cfg, _ := setupTestServer()
	handler := buildIntrospectHandler(server, cfg)

	req := httptest.NewRequest("PUT", "/introspect", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestIntrospectMissingTokenReturns400(t *testing.T) {
	server, cfg, _ := setupTestServer()
	handler := buildIntrospectHandler(server, cfg)

	// POST with empty body (no token parameter)
	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}
	if body["error"] != "invalid_request" {
		t.Fatalf("expected error=invalid_request, got %v", body["error"])
	}
	if body["error_description"] != "token parameter is required" {
		t.Fatalf("expected error_description='token parameter is required', got %v", body["error_description"])
	}
}

func TestIntrospectUnknownTokenReturnsInactive(t *testing.T) {
	server, cfg, _ := setupTestServer()
	handler := buildIntrospectHandler(server, cfg)

	form := url.Values{"token": {"nonexistent-token"}}
	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}
	if active, ok := body["active"].(bool); !ok || active {
		t.Fatalf("expected active=false for unknown token, got %v", body["active"])
	}
	// Should only contain "active" field
	if len(body) != 1 {
		t.Fatalf("expected only 'active' field for unknown token, got %v", body)
	}
}

func TestIntrospectValidAccessToken(t *testing.T) {
	server, cfg, _ := setupTestServer()
	handler := buildIntrospectHandler(server, cfg)

	form := url.Values{"token": {"valid-access-token"}}
	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}

	if active, ok := body["active"].(bool); !ok || !active {
		t.Fatalf("expected active=true for valid token, got %v", body["active"])
	}
	if body["client_id"] != "test-client" {
		t.Fatalf("expected client_id=test-client, got %v", body["client_id"])
	}
	if body["token_type"] != "Bearer" {
		t.Fatalf("expected token_type=Bearer, got %v", body["token_type"])
	}
	if body["scope"] != "read write" {
		t.Fatalf("expected scope='read write', got %v", body["scope"])
	}
	if _, ok := body["exp"]; !ok {
		t.Fatal("expected exp field to be present")
	}
	if _, ok := body["iat"]; !ok {
		t.Fatal("expected iat field to be present")
	}
}

func TestIntrospectExpiredTokenReturnsInactive(t *testing.T) {
	server, cfg, _ := setupTestServer()
	handler := buildIntrospectHandler(server, cfg)

	form := url.Values{"token": {"expired-token"}}
	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}

	if active, ok := body["active"].(bool); !ok || active {
		t.Fatalf("expected active=false for expired token, got %v", body["active"])
	}
	// Expired tokens still return metadata per RFC 7662
	if body["client_id"] != "test-client" {
		t.Fatalf("expected client_id=test-client for expired token, got %v", body["client_id"])
	}
}

func TestIntrospectTokenWithoutScope(t *testing.T) {
	server, cfg, _ := setupTestServer()
	handler := buildIntrospectHandler(server, cfg)

	form := url.Values{"token": {"no-scope-token"}}
	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}

	if _, ok := body["scope"]; ok {
		t.Fatalf("expected scope field to be absent for token without scope, got %v", body["scope"])
	}
	if active, ok := body["active"].(bool); !ok || !active {
		t.Fatalf("expected active=true, got %v", body["active"])
	}
}

func TestIntrospectRefreshTokenLookup(t *testing.T) {
	server, cfg, _ := setupTestServer()
	handler := buildIntrospectHandler(server, cfg)

	// Use refresh token with token_type_hint=refresh_token
	form := url.Values{
		"token":           {"valid-refresh-token"},
		"token_type_hint": {"refresh_token"},
	}
	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}

	if active, ok := body["active"].(bool); !ok || !active {
		t.Fatalf("expected active=true for valid refresh token, got %v", body["active"])
	}
	if body["client_id"] != "test-client" {
		t.Fatalf("expected client_id=test-client, got %v", body["client_id"])
	}
	if body["scope"] != "admin" {
		t.Fatalf("expected scope=admin, got %v", body["scope"])
	}
}

func TestIntrospectRefreshTokenWithoutHint(t *testing.T) {
	server, cfg, _ := setupTestServer()
	handler := buildIntrospectHandler(server, cfg)

	// Use refresh token WITHOUT token_type_hint (default path tries access first, then refresh)
	form := url.Values{
		"token": {"valid-refresh-token"},
	}
	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}

	// Should still find the token via refresh fallback
	if active, ok := body["active"].(bool); !ok || !active {
		t.Fatalf("expected active=true for refresh token found via fallback, got %v", body["active"])
	}
}

func TestIntrospectAccessTokenWithRefreshHint(t *testing.T) {
	server, cfg, _ := setupTestServer()
	handler := buildIntrospectHandler(server, cfg)

	// Use an access token but provide token_type_hint=refresh_token
	// The handler should still find it via the access token fallback
	form := url.Values{
		"token":           {"valid-access-token"},
		"token_type_hint": {"refresh_token"},
	}
	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}

	if active, ok := body["active"].(bool); !ok || !active {
		t.Fatalf("expected active=true for access token found via fallback in refresh_token hint path, got %v", body["active"])
	}
	if body["client_id"] != "test-client" {
		t.Fatalf("expected client_id=test-client, got %v", body["client_id"])
	}
}

func TestIntrospectExpTimestampCorrect(t *testing.T) {
	server, cfg, _ := setupTestServer()
	handler := buildIntrospectHandler(server, cfg)

	form := url.Values{"token": {"valid-access-token"}}
	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}

	// exp should be iat + ExpiresIn (3600 seconds)
	iat, ok := body["iat"].(float64)
	if !ok {
		t.Fatal("iat is not a number")
	}
	exp, ok := body["exp"].(float64)
	if !ok {
		t.Fatal("exp is not a number")
	}

	diff := exp - iat
	if diff != 3600 {
		t.Fatalf("expected exp - iat = 3600, got %v", diff)
	}
}

func TestIntrospectContentTypeHeader(t *testing.T) {
	server, cfg, _ := setupTestServer()
	handler := buildIntrospectHandler(server, cfg)

	// Check Content-Type on all response paths
	testCases := []struct {
		name   string
		method string
		body   string
	}{
		{"GET method", "GET", ""},
		{"missing token", "POST", ""},
		{"valid token", "POST", "token=valid-access-token"},
		{"unknown token", "POST", "token=bogus"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/introspect", strings.NewReader(tc.body))
			if tc.method == "POST" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			ct := rr.Header().Get("Content-Type")
			if ct != "application/json" {
				t.Fatalf("expected Content-Type application/json for %s, got %s", tc.name, ct)
			}
		})
	}
}

func TestIntrospectUnknownTokenTypeHint(t *testing.T) {
	server, cfg, _ := setupTestServer()
	handler := buildIntrospectHandler(server, cfg)

	// Unknown token_type_hint should use default path (access token first)
	form := url.Values{
		"token":           {"valid-access-token"},
		"token_type_hint": {"unknown_type"},
	}
	req := httptest.NewRequest("POST", "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}

	if active, ok := body["active"].(bool); !ok || !active {
		t.Fatalf("expected active=true with unknown hint for valid access token, got %v", body["active"])
	}
}
