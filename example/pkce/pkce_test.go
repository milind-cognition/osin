package main

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/openshift/osin"
	"github.com/openshift/osin/example"
)

func TestGenerateCodeVerifier(t *testing.T) {
	t.Run("returns base64url encoded string of correct length", func(t *testing.T) {
		verifier, err := generateCodeVerifier()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// 32 bytes base64url-encoded without padding = 43 characters
		if len(verifier) != 43 {
			t.Errorf("expected verifier length 43, got %d", len(verifier))
		}
	})

	t.Run("uses only base64url characters", func(t *testing.T) {
		verifier, err := generateCodeVerifier()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// base64url uses [A-Za-z0-9_-] without padding
		for _, c := range verifier {
			if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				t.Errorf("unexpected character in verifier: %c", c)
			}
		}
	})

	t.Run("generates unique verifiers", func(t *testing.T) {
		verifiers := make(map[string]bool)
		for i := 0; i < 100; i++ {
			v, err := generateCodeVerifier()
			if err != nil {
				t.Fatalf("unexpected error on iteration %d: %v", i, err)
			}
			if verifiers[v] {
				t.Errorf("duplicate verifier generated: %s", v)
			}
			verifiers[v] = true
		}
	})

	t.Run("can be decoded as valid base64url", func(t *testing.T) {
		verifier, err := generateCodeVerifier()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(verifier)
		if err != nil {
			t.Fatalf("verifier is not valid base64url: %v", err)
		}
		if len(decoded) != codeVerifierLength {
			t.Errorf("decoded length should be %d, got %d", codeVerifierLength, len(decoded))
		}
	})
}

func TestGenerateCodeChallenge(t *testing.T) {
	t.Run("produces correct S256 challenge for known verifier", func(t *testing.T) {
		// RFC 7636 Appendix B test vector
		verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		expected := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

		challenge := generateCodeChallenge(verifier)
		if challenge != expected {
			t.Errorf("expected challenge %q, got %q", expected, challenge)
		}
	})

	t.Run("is deterministic for same input", func(t *testing.T) {
		verifier := "test-verifier-value-1234567890abcdef"
		c1 := generateCodeChallenge(verifier)
		c2 := generateCodeChallenge(verifier)
		if c1 != c2 {
			t.Errorf("challenge should be deterministic: got %q and %q", c1, c2)
		}
	})

	t.Run("produces different challenges for different verifiers", func(t *testing.T) {
		c1 := generateCodeChallenge("verifier-one-aaaaaaaaaaaaaaaaaaa")
		c2 := generateCodeChallenge("verifier-two-bbbbbbbbbbbbbbbbbbb")
		if c1 == c2 {
			t.Errorf("different verifiers should produce different challenges")
		}
	})

	t.Run("output is valid base64url without padding", func(t *testing.T) {
		challenge := generateCodeChallenge("some-verifier-string-for-testing")
		// Should not contain padding characters or non-base64url chars
		if strings.ContainsAny(challenge, "+/=") {
			t.Errorf("challenge contains non-base64url characters: %s", challenge)
		}
		// SHA256 output is 32 bytes, base64url without padding = 43 chars
		if len(challenge) != 43 {
			t.Errorf("expected challenge length 43, got %d", len(challenge))
		}
	})

	t.Run("matches manual SHA256 computation", func(t *testing.T) {
		verifier := "my-test-code-verifier-abcdefghij"
		hash := sha256.Sum256([]byte(verifier))
		expected := base64.RawURLEncoding.EncodeToString(hash[:])

		challenge := generateCodeChallenge(verifier)
		if challenge != expected {
			t.Errorf("expected %q, got %q", expected, challenge)
		}
	})
}

func TestGenerateCodeVerifierAndChallengeIntegration(t *testing.T) {
	t.Run("generated verifier produces valid challenge for S256 verification", func(t *testing.T) {
		verifier, err := generateCodeVerifier()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		challenge := generateCodeChallenge(verifier)

		// Verify the challenge matches what S256 should produce
		hash := sha256.Sum256([]byte(verifier))
		expected := base64.RawURLEncoding.EncodeToString(hash[:])
		if challenge != expected {
			t.Errorf("challenge mismatch: got %q, want %q", challenge, expected)
		}

		// Verify the challenge is the right length (43 chars for base64url of SHA256)
		if len(challenge) != 43 {
			t.Errorf("challenge length should be 43, got %d", len(challenge))
		}
	})
}

// setupPKCEServer creates a test OAuth2 server configured for PKCE testing.
func setupPKCEServer() (*osin.Server, *example.TestStorage) {
	cfg := osin.NewServerConfig()
	cfg.AllowGetAccessRequest = true
	cfg.AllowClientSecretInParams = true
	cfg.RequirePKCEForPublicClients = true
	cfg.AllowedAuthorizeTypes = osin.AllowedAuthorizeType{osin.CODE}
	cfg.AllowedAccessTypes = osin.AllowedAccessType{osin.AUTHORIZATION_CODE}

	storage := example.NewTestStorage()
	storage.SetClient("pkce-client", &osin.DefaultClient{
		Id:          "pkce-client",
		Secret:      "",
		RedirectUri: "http://localhost:14000/appauth/code",
	})

	server := osin.NewServer(cfg, storage)
	return server, storage
}

func TestPKCEAuthorizeEndpoint(t *testing.T) {
	server, _ := setupPKCEServer()

	t.Run("public client with valid PKCE challenge succeeds", func(t *testing.T) {
		verifier, err := generateCodeVerifier()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		challenge := generateCodeChallenge(verifier)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := server.NewResponse()
			defer resp.Close()

			if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {
				ar.Authorized = true
				server.FinishAuthorizeRequest(resp, r, ar)
			}
			osin.OutputJSON(resp, w, r)
		})

		req := httptest.NewRequest("GET", "/authorize?"+url.Values{
			"response_type":         {"code"},
			"client_id":             {"pkce-client"},
			"state":                 {"pkce-state"},
			"redirect_uri":          {"http://localhost:14000/appauth/code"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}.Encode(), nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		// Should redirect (302) with an authorization code
		if rr.Code != http.StatusFound {
			t.Errorf("expected status 302, got %d", rr.Code)
		}
		location := rr.Header().Get("Location")
		if location == "" {
			t.Fatal("expected Location header in redirect response")
		}
		parsedURL, err := url.Parse(location)
		if err != nil {
			t.Fatalf("failed to parse redirect URL: %v", err)
		}
		code := parsedURL.Query().Get("code")
		if code == "" {
			t.Error("expected authorization code in redirect URL")
		}
	})

	t.Run("public client without PKCE challenge is rejected", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := server.NewResponse()
			defer resp.Close()

			if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {
				ar.Authorized = true
				server.FinishAuthorizeRequest(resp, r, ar)
			}
			osin.OutputJSON(resp, w, r)
		})

		req := httptest.NewRequest("GET", "/authorize?"+url.Values{
			"response_type": {"code"},
			"client_id":     {"pkce-client"},
			"state":         {"test-state"},
			"redirect_uri":  {"http://localhost:14000/appauth/code"},
		}.Encode(), nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		// Should return an error since PKCE is required for public clients
		// The server returns a JSON error response (200) when the client_id is invalid
		// or redirects with an error when PKCE is required
		if rr.Code == http.StatusFound {
			location := rr.Header().Get("Location")
			if location != "" {
				parsedURL, err := url.Parse(location)
				if err == nil {
					code := parsedURL.Query().Get("code")
					if code != "" {
						t.Error("public client without PKCE should not receive an authorization code")
					}
				}
			}
		}
	})
}

func TestPKCEFullFlowEndToEnd(t *testing.T) {
	server, _ := setupPKCEServer()

	verifier, err := generateCodeVerifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	challenge := generateCodeChallenge(verifier)

	// Step 1: Authorization request with PKCE challenge
	authorizeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {
			ar.Authorized = true
			ar.UserData = struct{ Login string }{Login: "test"}
			server.FinishAuthorizeRequest(resp, r, ar)
		}
		osin.OutputJSON(resp, w, r)
	})

	authReq := httptest.NewRequest("GET", "/authorize?"+url.Values{
		"response_type":         {"code"},
		"client_id":             {"pkce-client"},
		"state":                 {"pkce-state"},
		"redirect_uri":          {"http://localhost:14000/appauth/code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode(), nil)
	authRR := httptest.NewRecorder()
	authorizeHandler.ServeHTTP(authRR, authReq)

	if authRR.Code != http.StatusFound {
		t.Fatalf("authorize: expected status 302, got %d, body: %s", authRR.Code, authRR.Body.String())
	}

	location := authRR.Header().Get("Location")
	parsedURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse redirect URL: %v", err)
	}
	authCode := parsedURL.Query().Get("code")
	if authCode == "" {
		t.Fatal("expected authorization code in redirect")
	}

	// Step 2: Token exchange with code_verifier
	tokenHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ar := server.HandleAccessRequest(resp, r); ar != nil {
			ar.Authorized = true
			server.FinishAccessRequest(resp, r, ar)
		}
		osin.OutputJSON(resp, w, r)
	})

	tokenReq := httptest.NewRequest("POST", "/token", strings.NewReader(url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"pkce-client"},
		"code":          {authCode},
		"redirect_uri":  {"http://localhost:14000/appauth/code"},
		"code_verifier": {verifier},
	}.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth("pkce-client", "")
	tokenRR := httptest.NewRecorder()
	tokenHandler.ServeHTTP(tokenRR, tokenReq)

	if tokenRR.Code != http.StatusOK {
		t.Fatalf("token: expected status 200, got %d, body: %s", tokenRR.Code, tokenRR.Body.String())
	}

	body := tokenRR.Body.String()
	if !strings.Contains(body, "access_token") {
		t.Errorf("expected access_token in response, got: %s", body)
	}
}

func TestPKCETokenExchangeWithWrongVerifier(t *testing.T) {
	server, _ := setupPKCEServer()

	verifier, err := generateCodeVerifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	challenge := generateCodeChallenge(verifier)

	// Step 1: Authorize with correct challenge
	authorizeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {
			ar.Authorized = true
			server.FinishAuthorizeRequest(resp, r, ar)
		}
		osin.OutputJSON(resp, w, r)
	})

	authReq := httptest.NewRequest("GET", "/authorize?"+url.Values{
		"response_type":         {"code"},
		"client_id":             {"pkce-client"},
		"state":                 {"pkce-state"},
		"redirect_uri":          {"http://localhost:14000/appauth/code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode(), nil)
	authRR := httptest.NewRecorder()
	authorizeHandler.ServeHTTP(authRR, authReq)

	location := authRR.Header().Get("Location")
	parsedURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse redirect URL: %v", err)
	}
	authCode := parsedURL.Query().Get("code")
	if authCode == "" {
		t.Fatal("expected authorization code")
	}

	// Step 2: Token exchange with WRONG verifier
	tokenHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ar := server.HandleAccessRequest(resp, r); ar != nil {
			ar.Authorized = true
			server.FinishAccessRequest(resp, r, ar)
		}
		osin.OutputJSON(resp, w, r)
	})

	wrongVerifier := "this-is-a-completely-wrong-verifier-value-"
	tokenReq := httptest.NewRequest("POST", "/token", strings.NewReader(url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"pkce-client"},
		"code":          {authCode},
		"redirect_uri":  {"http://localhost:14000/appauth/code"},
		"code_verifier": {wrongVerifier},
	}.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth("pkce-client", "")
	tokenRR := httptest.NewRecorder()
	tokenHandler.ServeHTTP(tokenRR, tokenReq)

	body := tokenRR.Body.String()
	// Should contain an error, not an access_token
	if strings.Contains(body, "access_token") {
		t.Errorf("wrong verifier should not produce an access token, got: %s", body)
	}
	if !strings.Contains(body, "error") {
		t.Errorf("expected error in response for wrong verifier, got: %s", body)
	}
}

func TestPKCETokenExchangeWithoutVerifier(t *testing.T) {
	server, _ := setupPKCEServer()

	verifier, err := generateCodeVerifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	challenge := generateCodeChallenge(verifier)

	// Step 1: Authorize with PKCE challenge
	authorizeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {
			ar.Authorized = true
			server.FinishAuthorizeRequest(resp, r, ar)
		}
		osin.OutputJSON(resp, w, r)
	})

	authReq := httptest.NewRequest("GET", "/authorize?"+url.Values{
		"response_type":         {"code"},
		"client_id":             {"pkce-client"},
		"state":                 {"pkce-state"},
		"redirect_uri":          {"http://localhost:14000/appauth/code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode(), nil)
	authRR := httptest.NewRecorder()
	authorizeHandler.ServeHTTP(authRR, authReq)

	location := authRR.Header().Get("Location")
	parsedURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse redirect URL: %v", err)
	}
	authCode := parsedURL.Query().Get("code")

	// Step 2: Token exchange WITHOUT verifier
	tokenHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ar := server.HandleAccessRequest(resp, r); ar != nil {
			ar.Authorized = true
			server.FinishAccessRequest(resp, r, ar)
		}
		osin.OutputJSON(resp, w, r)
	})

	tokenReq := httptest.NewRequest("POST", "/token", strings.NewReader(url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {"pkce-client"},
		"code":         {authCode},
		"redirect_uri": {"http://localhost:14000/appauth/code"},
	}.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth("pkce-client", "")
	tokenRR := httptest.NewRecorder()
	tokenHandler.ServeHTTP(tokenRR, tokenReq)

	body := tokenRR.Body.String()
	if strings.Contains(body, "access_token") {
		t.Errorf("missing verifier should not produce an access token, got: %s", body)
	}
	if !strings.Contains(body, "error") {
		t.Errorf("expected error for missing verifier, got: %s", body)
	}
}
