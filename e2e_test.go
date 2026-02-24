package osin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// =============================================================================
// Full E2E Flows
// =============================================================================

// TestE2EAuthorizationCodeFlow tests the complete authorization code flow:
// 1. Client requests authorization code
// 2. Client exchanges code for access token
// 3. Client uses access token to get info
func TestE2EAuthorizationCodeFlow(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, NewTestingStorage())
	server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}
	server.AccessTokenGen = &TestingAccessTokenGen{}

	// Step 1: Get authorization code
	resp := server.NewResponse()
	req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "mystate")
	req.Form.Set("scope", "read write")

	if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAuthorizeRequest(resp, req, ar)
	}

	if resp.IsError {
		t.Fatalf("Step 1 failed: %v", resp.InternalError)
	}
	if resp.Type != REDIRECT {
		t.Fatalf("Step 1: expected redirect, got %v", resp.Type)
	}

	code, ok := resp.Output["code"].(string)
	if !ok || code == "" {
		t.Fatalf("Step 1: no authorization code returned")
	}
	if resp.Output["state"] != "mystate" {
		t.Fatalf("Step 1: state mismatch: %v", resp.Output["state"])
	}
	resp.Close()

	// Step 2: Exchange code for access token
	resp2 := server.NewResponse()
	req2, err := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.SetBasicAuth("1234", "aabbccdd")
	req2.Form = make(url.Values)
	req2.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req2.Form.Set("code", code)
	req2.Form.Set("redirect_uri", "http://localhost:14000/appauth")
	req2.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp2, req2); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp2, req2, ar)
	}

	if resp2.IsError {
		t.Fatalf("Step 2 failed: error=%v, internal=%v", resp2.ErrorId, resp2.InternalError)
	}
	if resp2.Type != DATA {
		t.Fatalf("Step 2: expected data response")
	}

	accessToken, ok := resp2.Output["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatalf("Step 2: no access token returned")
	}
	if resp2.Output["token_type"] != "Bearer" {
		t.Fatalf("Step 2: expected Bearer token type, got %v", resp2.Output["token_type"])
	}
	if resp2.Output["scope"] != "read write" {
		t.Fatalf("Step 2: expected scope 'read write', got %v", resp2.Output["scope"])
	}
	resp2.Close()

	// Step 3: Use access token for info request
	resp3 := server.NewResponse()
	req3, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req3.Header.Set("Authorization", "Bearer "+accessToken)

	if ir := server.HandleInfoRequest(resp3, req3); ir != nil {
		server.FinishInfoRequest(resp3, req3, ir)
	}

	if resp3.IsError {
		t.Fatalf("Step 3 failed: error=%v, internal=%v", resp3.ErrorId, resp3.InternalError)
	}
	if resp3.Output["access_token"] != accessToken {
		t.Fatalf("Step 3: access token mismatch")
	}
	if resp3.Output["client_id"] != "1234" {
		t.Fatalf("Step 3: client_id mismatch: %v", resp3.Output["client_id"])
	}
	resp3.Close()

	// Verify the authorization code was consumed (removed from storage)
	if _, err := server.Storage.LoadAuthorize(code); err == nil {
		t.Fatalf("Authorization code should have been removed after token exchange")
	}
}

// TestE2EImplicitFlow tests the complete implicit grant flow
func TestE2EImplicitFlow(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{TOKEN}
	server := NewServer(sconfig, NewTestingStorage())
	server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}
	server.AccessTokenGen = &TestingAccessTokenGen{}

	resp := server.NewResponse()
	req, err := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(TOKEN))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "implicitstate")
	req.Form.Set("scope", "profile")

	if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAuthorizeRequest(resp, req, ar)
	}

	if resp.IsError {
		t.Fatalf("Error in implicit flow: %v", resp.InternalError)
	}
	if resp.Type != REDIRECT {
		t.Fatalf("Expected redirect response")
	}
	if !resp.RedirectInFragment {
		t.Fatalf("Expected redirect in fragment for implicit flow")
	}

	accessToken, ok := resp.Output["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatalf("No access token in implicit flow")
	}
	if resp.Output["state"] != "implicitstate" {
		t.Fatalf("State mismatch in implicit flow: %v", resp.Output["state"])
	}

	// Verify the token is stored and can be used for info
	resp2 := server.NewResponse()
	req2, err := http.NewRequest("GET", "http://localhost:14000/info", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Authorization", "Bearer "+accessToken)

	if ir := server.HandleInfoRequest(resp2, req2); ir != nil {
		server.FinishInfoRequest(resp2, req2, ir)
	}

	if resp2.IsError {
		t.Fatalf("Info request failed for implicit token: %v", resp2.InternalError)
	}
	if resp2.Output["access_token"] != accessToken {
		t.Fatalf("Access token mismatch in info response")
	}
	resp.Close()
	resp2.Close()
}

// TestE2ERefreshTokenFlow tests getting a token then refreshing it
func TestE2ERefreshTokenFlow(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE, REFRESH_TOKEN}
	server := NewServer(sconfig, NewTestingStorage())
	server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}
	server.AccessTokenGen = &TestingAccessTokenGen{}

	// Step 1: Get auth code
	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "a")

	if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAuthorizeRequest(resp, req, ar)
	}
	code := resp.Output["code"].(string)
	resp.Close()

	// Step 2: Exchange code for token
	resp2 := server.NewResponse()
	req2, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req2.SetBasicAuth("1234", "aabbccdd")
	req2.Form = make(url.Values)
	req2.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req2.Form.Set("code", code)
	req2.Form.Set("redirect_uri", "http://localhost:14000/appauth")
	req2.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp2, req2); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp2, req2, ar)
	}

	if resp2.IsError {
		t.Fatalf("Token exchange failed: %v", resp2.InternalError)
	}
	refreshToken, ok := resp2.Output["refresh_token"].(string)
	if !ok || refreshToken == "" {
		t.Fatalf("No refresh token returned")
	}
	originalAccessToken := resp2.Output["access_token"].(string)
	resp2.Close()

	// Step 3: Use refresh token to get new access token
	resp3 := server.NewResponse()
	req3, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req3.SetBasicAuth("1234", "aabbccdd")
	req3.Form = make(url.Values)
	req3.Form.Set("grant_type", string(REFRESH_TOKEN))
	req3.Form.Set("refresh_token", refreshToken)
	req3.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp3, req3); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp3, req3, ar)
	}

	if resp3.IsError {
		t.Fatalf("Refresh token exchange failed: %v", resp3.InternalError)
	}
	newAccessToken := resp3.Output["access_token"].(string)
	if newAccessToken == originalAccessToken {
		t.Fatalf("New access token should be different from original")
	}
	newRefreshToken := resp3.Output["refresh_token"].(string)
	if newRefreshToken == "" {
		t.Fatalf("Expected new refresh token")
	}
	resp3.Close()
}

// TestE2EPasswordGrantFlow tests the resource owner password credentials flow
func TestE2EPasswordGrantFlow(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{PASSWORD}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGen = &TestingAccessTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(PASSWORD))
	req.Form.Set("username", "testuser")
	req.Form.Set("password", "testpass")
	req.Form.Set("scope", "admin")
	req.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		ar.Authorized = (ar.Username == "testuser" && ar.Password == "testpass")
		server.FinishAccessRequest(resp, req, ar)
	}

	if resp.IsError {
		t.Fatalf("Password grant failed: %v", resp.InternalError)
	}
	if resp.Output["access_token"] == nil {
		t.Fatalf("No access token")
	}
	if resp.Output["scope"] != "admin" {
		t.Fatalf("Expected scope 'admin', got %v", resp.Output["scope"])
	}
	resp.Close()
}

// TestE2EClientCredentialsGrantFlow tests the client credentials flow
func TestE2EClientCredentialsGrantFlow(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{CLIENT_CREDENTIALS}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGen = &TestingAccessTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(CLIENT_CREDENTIALS))
	req.Form.Set("scope", "service")
	req.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp, req, ar)
	}

	if resp.IsError {
		t.Fatalf("Client credentials grant failed: %v", resp.InternalError)
	}
	if resp.Output["access_token"] == nil {
		t.Fatalf("No access token")
	}
	if _, ok := resp.Output["refresh_token"]; ok {
		t.Fatalf("Client credentials should not return refresh token")
	}
	if resp.Output["scope"] != "service" {
		t.Fatalf("Expected scope 'service', got %v", resp.Output["scope"])
	}
	resp.Close()
}

// TestE2EAssertionGrantFlow tests the assertion grant type
func TestE2EAssertionGrantFlow(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{ASSERTION}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGen = &TestingAccessTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(ASSERTION))
	req.Form.Set("assertion_type", "urn:osin:custom")
	req.Form.Set("assertion", "my-assertion-data")
	req.Form.Set("scope", "read")
	req.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		if ar.AssertionType != "urn:osin:custom" {
			t.Fatalf("Expected assertion_type 'urn:osin:custom', got '%s'", ar.AssertionType)
		}
		if ar.Assertion != "my-assertion-data" {
			t.Fatalf("Expected assertion 'my-assertion-data', got '%s'", ar.Assertion)
		}
		ar.Authorized = true
		server.FinishAccessRequest(resp, req, ar)
	}

	if resp.IsError {
		t.Fatalf("Assertion grant failed: %v", resp.InternalError)
	}
	if resp.Output["access_token"] == nil {
		t.Fatalf("No access token")
	}
	// Assertion should NOT generate refresh token per RFC
	if _, ok := resp.Output["refresh_token"]; ok {
		t.Fatalf("Assertion grant should not return refresh token")
	}
	resp.Close()
}

// =============================================================================
// Access Request Error Paths
// =============================================================================

// TestAccessRequestGETNotAllowed tests that GET is rejected when not configured
func TestAccessRequestGETNotAllowed(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	sconfig.AllowGetAccessRequest = false
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/appauth?grant_type=authorization_code&code=9999", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.ParseForm()

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not have returned an access request for GET")
	}
	if !resp.IsError {
		t.Fatalf("Expected error response")
	}
	if resp.ErrorId != E_INVALID_REQUEST {
		t.Fatalf("Expected invalid_request, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestAccessRequestGETAllowed tests that GET works when configured
func TestAccessRequestGETAllowed(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	sconfig.AllowGetAccessRequest = true
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGen = &TestingAccessTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/appauth?grant_type=authorization_code&code=9999", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.ParseForm()

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp, req, ar)
	}

	if resp.IsError {
		t.Fatalf("GET access request should succeed when allowed: %v", resp.InternalError)
	}
	if resp.Output["access_token"] == nil {
		t.Fatalf("Expected access token in response")
	}
	resp.Close()
}

// TestAccessRequestInvalidMethod tests that PUT/DELETE are rejected
func TestAccessRequestInvalidMethod(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, NewTestingStorage())

	for _, method := range []string{"PUT", "DELETE", "PATCH"} {
		resp := server.NewResponse()
		req, _ := http.NewRequest(method, "http://localhost:14000/appauth", nil)
		req.SetBasicAuth("1234", "aabbccdd")
		req.Form = make(url.Values)
		req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
		req.Form.Set("code", "9999")
		req.PostForm = make(url.Values)

		ar := server.HandleAccessRequest(resp, req)
		if ar != nil {
			t.Fatalf("Method %s: should not return access request", method)
		}
		if !resp.IsError {
			t.Fatalf("Method %s: expected error", method)
		}
		if resp.ErrorId != E_INVALID_REQUEST {
			t.Fatalf("Method %s: expected invalid_request, got %s", method, resp.ErrorId)
		}
		resp.Close()
	}
}

// TestAccessRequestUnsupportedGrantType tests requesting an unsupported grant type
func TestAccessRequestUnsupportedGrantType(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(PASSWORD)) // not allowed
	req.Form.Set("username", "test")
	req.Form.Set("password", "test")
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request for unsupported grant type")
	}
	if !resp.IsError {
		t.Fatalf("Expected error for unsupported grant type")
	}
	if resp.ErrorId != E_UNSUPPORTED_GRANT_TYPE {
		t.Fatalf("Expected unsupported_grant_type, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestAccessAuthCodeMissingCode tests auth code request without code
func TestAccessAuthCodeMissingCode(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	// no code set
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request without code")
	}
	if !resp.IsError {
		t.Fatalf("Expected error")
	}
	if resp.ErrorId != E_INVALID_GRANT {
		t.Fatalf("Expected invalid_grant, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestAccessAuthCodeExpired tests using an expired authorization code
func TestAccessAuthCodeExpired(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	testStorage := NewTestingStorage()
	server := NewServer(sconfig, testStorage)
	server.AccessTokenGen = &TestingAccessTokenGen{}

	// Save an expired auth code
	testStorage.SaveAuthorize(&AuthorizeData{
		Client:      testStorage.clients["1234"],
		Code:        "expired-code",
		ExpiresIn:   1,
		CreatedAt:   time.Now().Add(-time.Hour),
		RedirectUri: "http://localhost:14000/appauth",
	})

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "expired-code")
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request for expired code")
	}
	if !resp.IsError {
		t.Fatalf("Expected error for expired code")
	}
	if resp.ErrorId != E_INVALID_GRANT {
		t.Fatalf("Expected invalid_grant, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestAccessAuthCodeClientMismatch tests using a code from a different client
func TestAccessAuthCodeClientMismatch(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	testStorage := NewTestingStorage()
	server := NewServer(sconfig, testStorage)
	server.AccessTokenGen = &TestingAccessTokenGen{}

	// Save auth code for public-client
	testStorage.SaveAuthorize(&AuthorizeData{
		Client:      testStorage.clients["public-client"],
		Code:        "other-client-code",
		ExpiresIn:   3600,
		CreatedAt:   time.Now(),
		RedirectUri: "http://localhost:14000/appauth",
	})

	// Try to use code with client "1234"
	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "other-client-code")
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request for mismatched client")
	}
	if !resp.IsError {
		t.Fatalf("Expected error for client mismatch")
	}
	if resp.ErrorId != E_INVALID_GRANT {
		t.Fatalf("Expected invalid_grant, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestAccessAuthCodeRedirectURIMismatch tests mismatched redirect URIs
func TestAccessAuthCodeRedirectURIMismatch(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	testStorage := NewTestingStorage()
	server := NewServer(sconfig, testStorage)
	server.AccessTokenGen = &TestingAccessTokenGen{}

	testStorage.SaveAuthorize(&AuthorizeData{
		Client:      testStorage.clients["1234"],
		Code:        "redirect-mismatch-code",
		ExpiresIn:   3600,
		CreatedAt:   time.Now(),
		RedirectUri: "http://localhost:14000/appauth",
	})

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "redirect-mismatch-code")
	req.Form.Set("redirect_uri", "http://localhost:14000/different")
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request for redirect URI mismatch")
	}
	if !resp.IsError {
		t.Fatalf("Expected error for redirect URI mismatch")
	}
	resp.Close()
}

// TestAccessRefreshTokenMissing tests refresh request without token
func TestAccessRefreshTokenMissing(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{REFRESH_TOKEN}
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(REFRESH_TOKEN))
	// no refresh_token
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request without refresh token")
	}
	if !resp.IsError {
		t.Fatalf("Expected error")
	}
	if resp.ErrorId != E_INVALID_GRANT {
		t.Fatalf("Expected invalid_grant, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestAccessRefreshTokenClientMismatch tests using a refresh token from a different client
func TestAccessRefreshTokenClientMismatch(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{REFRESH_TOKEN}
	testStorage := NewTestingStorage()
	server := NewServer(sconfig, testStorage)

	// Create another client
	otherClient := &DefaultClient{
		Id:          "other-client",
		Secret:      "othersecret",
		RedirectUri: "http://localhost:14000/appauth",
	}
	testStorage.SetClient("other-client", otherClient)

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("other-client", "othersecret")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(REFRESH_TOKEN))
	req.Form.Set("refresh_token", "r9999") // belongs to client "1234"
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request for mismatched client")
	}
	if !resp.IsError {
		t.Fatalf("Expected error for client mismatch")
	}
	if resp.ErrorId != E_INVALID_CLIENT {
		t.Fatalf("Expected invalid_client, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestAccessRefreshTokenExtraScopes tests requesting extra scopes on refresh
func TestAccessRefreshTokenExtraScopes(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{REFRESH_TOKEN}
	testStorage := NewTestingStorage()
	server := NewServer(sconfig, testStorage)
	server.AccessTokenGen = &TestingAccessTokenGen{}

	// Create access data with limited scope and a refresh token
	testStorage.access["scoped-access"] = &AccessData{
		Client:       testStorage.clients["1234"],
		AccessToken:  "scoped-access",
		RefreshToken: "scoped-refresh",
		ExpiresIn:    3600,
		CreatedAt:    time.Now(),
		Scope:        "read",
		RedirectUri:  "http://localhost:14000/appauth",
	}
	testStorage.refresh["scoped-refresh"] = "scoped-access"

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(REFRESH_TOKEN))
	req.Form.Set("refresh_token", "scoped-refresh")
	req.Form.Set("scope", "read write") // requesting more scope than originally granted
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request for extra scopes")
	}
	if !resp.IsError {
		t.Fatalf("Expected error for extra scopes")
	}
	if resp.ErrorId != E_ACCESS_DENIED {
		t.Fatalf("Expected access_denied, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestAccessPasswordMissingCredentials tests password grant without credentials
func TestAccessPasswordMissingCredentials(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{PASSWORD}
	server := NewServer(sconfig, NewTestingStorage())

	tests := []struct {
		name     string
		username string
		password string
	}{
		{"missing both", "", ""},
		{"missing username", "", "pass"},
		{"missing password", "user", ""},
	}

	for _, tt := range tests {
		resp := server.NewResponse()
		req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
		req.SetBasicAuth("1234", "aabbccdd")
		req.Form = make(url.Values)
		req.Form.Set("grant_type", string(PASSWORD))
		req.Form.Set("username", tt.username)
		req.Form.Set("password", tt.password)
		req.PostForm = make(url.Values)

		ar := server.HandleAccessRequest(resp, req)
		if ar != nil {
			t.Fatalf("%s: should not return request", tt.name)
		}
		if !resp.IsError {
			t.Fatalf("%s: expected error", tt.name)
		}
		if resp.ErrorId != E_INVALID_GRANT {
			t.Fatalf("%s: expected invalid_grant, got %s", tt.name, resp.ErrorId)
		}
		resp.Close()
	}
}

// TestAccessAssertionMissingFields tests assertion grant with missing fields
func TestAccessAssertionMissingFields(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{ASSERTION}
	server := NewServer(sconfig, NewTestingStorage())

	tests := []struct {
		name          string
		assertionType string
		assertion     string
	}{
		{"missing both", "", ""},
		{"missing assertion_type", "", "some-assertion"},
		{"missing assertion", "urn:type", ""},
	}

	for _, tt := range tests {
		resp := server.NewResponse()
		req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
		req.SetBasicAuth("1234", "aabbccdd")
		req.Form = make(url.Values)
		req.Form.Set("grant_type", string(ASSERTION))
		req.Form.Set("assertion_type", tt.assertionType)
		req.Form.Set("assertion", tt.assertion)
		req.PostForm = make(url.Values)

		ar := server.HandleAccessRequest(resp, req)
		if ar != nil {
			t.Fatalf("%s: should not return request", tt.name)
		}
		if !resp.IsError {
			t.Fatalf("%s: expected error", tt.name)
		}
		if resp.ErrorId != E_INVALID_GRANT {
			t.Fatalf("%s: expected invalid_grant, got %s", tt.name, resp.ErrorId)
		}
		resp.Close()
	}
}

// TestAccessRequestInvalidClientAuth tests access request with bad client credentials
func TestAccessRequestInvalidClientAuth(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "wrongsecret")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "9999")
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request with invalid client auth")
	}
	if !resp.IsError {
		t.Fatalf("Expected error for invalid client auth")
	}
	if resp.ErrorId != E_UNAUTHORIZED_CLIENT {
		t.Fatalf("Expected unauthorized_client, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestAccessRequestNoAuth tests access request without any authentication
func TestAccessRequestNoAuth(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	// No auth set
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "9999")
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request without auth")
	}
	if !resp.IsError {
		t.Fatalf("Expected error for missing auth")
	}
	if resp.ErrorId != E_INVALID_REQUEST {
		t.Fatalf("Expected invalid_request, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestAccessRequestClientSecretInParams tests AllowClientSecretInParams
func TestAccessRequestClientSecretInParams(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	sconfig.AllowClientSecretInParams = true
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGen = &TestingAccessTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	// No basic auth - using params instead
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "9999")
	req.Form.Set("client_id", "1234")
	req.Form.Set("client_secret", "aabbccdd")
	req.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp, req, ar)
	}

	if resp.IsError {
		t.Fatalf("Should accept client secret in params: %v", resp.InternalError)
	}
	if resp.Output["access_token"] == nil {
		t.Fatalf("Expected access token")
	}
	resp.Close()
}

// TestFinishAccessRequestNotAuthorized tests denying access
func TestFinishAccessRequestNotAuthorized(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGen = &TestingAccessTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "9999")
	req.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		ar.Authorized = false // explicitly deny
		server.FinishAccessRequest(resp, req, ar)
	}

	if !resp.IsError {
		t.Fatalf("Expected error when not authorized")
	}
	if resp.ErrorId != E_ACCESS_DENIED {
		t.Fatalf("Expected access_denied, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestFinishAccessRequestAlreadyError tests FinishAccessRequest when response already has an error
func TestFinishAccessRequestAlreadyError(t *testing.T) {
	sconfig := NewServerConfig()
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGen = &TestingAccessTokenGen{}

	resp := server.NewResponse()
	resp.SetError(E_SERVER_ERROR, "pre-existing error")

	ar := &AccessRequest{
		Type:       AUTHORIZATION_CODE,
		Client:     &DefaultClient{Id: "1234", Secret: "aabbccdd", RedirectUri: "http://localhost:14000/appauth"},
		Authorized: true,
		Expiration: 3600,
	}

	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	server.FinishAccessRequest(resp, req, ar)

	// Should still have the original error, not overwrite it
	if resp.ErrorId != E_SERVER_ERROR {
		t.Fatalf("Expected original error to be preserved, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestFinishAccessRequestForceAccessData tests the ForceAccessData field
func TestFinishAccessRequestForceAccessData(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGen = &TestingAccessTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "9999")
	req.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		ar.Authorized = true
		ar.ForceAccessData = &AccessData{
			Client:       ar.Client,
			AccessToken:  "forced-token",
			RefreshToken: "forced-refresh",
			ExpiresIn:    7200,
			CreatedAt:    time.Now(),
			RedirectUri:  "http://localhost:14000/appauth",
		}
		server.FinishAccessRequest(resp, req, ar)
	}

	if resp.IsError {
		t.Fatalf("Error with ForceAccessData: %v", resp.InternalError)
	}
	if resp.Output["access_token"] != "forced-token" {
		t.Fatalf("Expected forced-token, got %v", resp.Output["access_token"])
	}
	if resp.Output["refresh_token"] != "forced-refresh" {
		t.Fatalf("Expected forced-refresh, got %v", resp.Output["refresh_token"])
	}
	resp.Close()
}

// TestAccessRefreshTokenInheritsScope tests that refresh token inherits scope when not specified
func TestAccessRefreshTokenInheritsScope(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{REFRESH_TOKEN}
	testStorage := NewTestingStorage()
	server := NewServer(sconfig, testStorage)
	server.AccessTokenGen = &TestingAccessTokenGen{}

	// Create access data with scope and a refresh token
	testStorage.access["inherit-access"] = &AccessData{
		Client:       testStorage.clients["1234"],
		AccessToken:  "inherit-access",
		RefreshToken: "inherit-refresh",
		ExpiresIn:    3600,
		CreatedAt:    time.Now(),
		Scope:        "read write",
		RedirectUri:  "http://localhost:14000/appauth",
	}
	testStorage.refresh["inherit-refresh"] = "inherit-access"

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(REFRESH_TOKEN))
	req.Form.Set("refresh_token", "inherit-refresh")
	// No scope specified - should inherit
	req.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		if ar.Scope != "read write" {
			t.Fatalf("Expected inherited scope 'read write', got '%s'", ar.Scope)
		}
		ar.Authorized = true
		server.FinishAccessRequest(resp, req, ar)
	}

	if resp.IsError {
		t.Fatalf("Error: %v", resp.InternalError)
	}
	if resp.Output["scope"] != "read write" {
		t.Fatalf("Expected scope 'read write' in output, got %v", resp.Output["scope"])
	}
	resp.Close()
}

// TestAccessRefreshTokenNarrowScope tests refreshing with a narrower scope
func TestAccessRefreshTokenNarrowScope(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{REFRESH_TOKEN}
	testStorage := NewTestingStorage()
	server := NewServer(sconfig, testStorage)
	server.AccessTokenGen = &TestingAccessTokenGen{}

	// Create access data with broad scope and a refresh token
	testStorage.access["narrow-access"] = &AccessData{
		Client:       testStorage.clients["1234"],
		AccessToken:  "narrow-access",
		RefreshToken: "narrow-refresh",
		ExpiresIn:    3600,
		CreatedAt:    time.Now(),
		Scope:        "read write",
		RedirectUri:  "http://localhost:14000/appauth",
	}
	testStorage.refresh["narrow-refresh"] = "narrow-access"

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(REFRESH_TOKEN))
	req.Form.Set("refresh_token", "narrow-refresh")
	req.Form.Set("scope", "read") // narrower scope - should be allowed
	req.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp, req, ar)
	}

	if resp.IsError {
		t.Fatalf("Narrower scope should be allowed: %v", resp.InternalError)
	}
	if resp.Output["scope"] != "read" {
		t.Fatalf("Expected scope 'read', got %v", resp.Output["scope"])
	}
	resp.Close()
}

// TestAccessAuthCodeNonexistentCode tests using a code that doesn't exist
func TestAccessAuthCodeNonexistentCode(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "nonexistent-code")
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request for nonexistent code")
	}
	if !resp.IsError {
		t.Fatalf("Expected error for nonexistent code")
	}
	resp.Close()
}

// TestAccessRefreshTokenNonexistent tests refreshing with a nonexistent token
func TestAccessRefreshTokenNonexistent(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{REFRESH_TOKEN}
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(REFRESH_TOKEN))
	req.Form.Set("refresh_token", "nonexistent-token")
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request for nonexistent refresh token")
	}
	if !resp.IsError {
		t.Fatalf("Expected error")
	}
	resp.Close()
}

// =============================================================================
// Authorize Request Error Paths
// =============================================================================

// TestAuthorizeRequestMissingClientId tests authorize with missing client_id
func TestAuthorizeRequestMissingClientId(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	// no client_id

	ar := server.HandleAuthorizeRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request without client_id")
	}
	if !resp.IsError {
		t.Fatalf("Expected error")
	}
	if resp.ErrorId != E_UNAUTHORIZED_CLIENT {
		t.Fatalf("Expected unauthorized_client, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestAuthorizeRequestUnsupportedResponseType tests an unsupported response_type
func TestAuthorizeRequestUnsupportedResponseType(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE} // only CODE
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(TOKEN)) // not allowed
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "a")

	ar := server.HandleAuthorizeRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request for unsupported response type")
	}
	if !resp.IsError {
		t.Fatalf("Expected error")
	}
	if resp.ErrorId != E_UNSUPPORTED_RESPONSE_TYPE {
		t.Fatalf("Expected unsupported_response_type, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestAuthorizeRequestNotAuthorized tests denying the authorize request
func TestAuthorizeRequestNotAuthorized(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	server := NewServer(sconfig, NewTestingStorage())
	server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "mystate")

	if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
		ar.Authorized = false // deny
		server.FinishAuthorizeRequest(resp, req, ar)
	}

	if !resp.IsError {
		t.Fatalf("Expected error when not authorized")
	}
	if resp.ErrorId != E_ACCESS_DENIED {
		t.Fatalf("Expected access_denied, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestAuthorizeFinishAlreadyError tests FinishAuthorizeRequest when response already has an error
func TestAuthorizeFinishAlreadyError(t *testing.T) {
	sconfig := NewServerConfig()
	server := NewServer(sconfig, NewTestingStorage())
	server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}

	resp := server.NewResponse()
	resp.SetError(E_SERVER_ERROR, "pre-existing error")

	ar := &AuthorizeRequest{
		Type:       CODE,
		Client:     &DefaultClient{Id: "1234", Secret: "aabbccdd", RedirectUri: "http://localhost:14000/appauth"},
		Authorized: true,
		Expiration: 300,
	}

	req, _ := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	server.FinishAuthorizeRequest(resp, req, ar)

	if resp.ErrorId != E_SERVER_ERROR {
		t.Fatalf("Expected original error to be preserved, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestAuthorizeCodePKCEInvalidChallengeMethod tests invalid PKCE challenge method
func TestAuthorizeCodePKCEInvalidChallengeMethod(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	server := NewServer(sconfig, NewTestingStorage())
	server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "a")
	req.Form.Set("code_challenge", "12345678901234567890123456789012345678901234567890")
	req.Form.Set("code_challenge_method", "unsupported-method")

	ar := server.HandleAuthorizeRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request for invalid challenge method")
	}
	if !resp.IsError {
		t.Fatalf("Expected error for invalid challenge method")
	}
	if resp.ErrorId != E_INVALID_REQUEST {
		t.Fatalf("Expected invalid_request, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestAuthorizeCodePKCEInvalidChallengeFormat tests invalid PKCE challenge format
func TestAuthorizeCodePKCEInvalidChallengeFormat(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	server := NewServer(sconfig, NewTestingStorage())
	server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "a")
	req.Form.Set("code_challenge", "too-short") // must be 43-128 chars

	ar := server.HandleAuthorizeRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request for invalid challenge format")
	}
	if !resp.IsError {
		t.Fatalf("Expected error for invalid challenge format")
	}
	if resp.ErrorId != E_INVALID_REQUEST {
		t.Fatalf("Expected invalid_request, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestAuthorizeCodeWithMultipleRedirectURIs tests handling of multiple redirect URIs with separator
func TestAuthorizeCodeWithMultipleRedirectURIs(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	sconfig.RedirectUriSeparator = ";"
	testStorage := NewTestingStorage()
	server := NewServer(sconfig, testStorage)
	server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}

	// Set up client with multiple redirect URIs
	testStorage.clients["multi-redir"] = &DefaultClient{
		Id:          "multi-redir",
		Secret:      "secret",
		RedirectUri: "http://localhost:14000/appauth;http://localhost:14000/other",
	}

	// Request with one of the valid redirect URIs
	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "multi-redir")
	req.Form.Set("redirect_uri", "http://localhost:14000/other")
	req.Form.Set("state", "a")

	if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAuthorizeRequest(resp, req, ar)
	}

	if resp.IsError {
		t.Fatalf("Expected success with valid redirect URI from list: %v", resp.InternalError)
	}
	if resp.Output["code"] == nil {
		t.Fatalf("Expected authorization code")
	}
	resp.Close()
}

// TestAuthorizeRequestInvalidRedirectURI tests authorize with invalid redirect URI
func TestAuthorizeRequestInvalidRedirectURI(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")
	req.Form.Set("redirect_uri", "http://evil.com/steal")
	req.Form.Set("state", "a")

	ar := server.HandleAuthorizeRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request with invalid redirect URI")
	}
	if !resp.IsError {
		t.Fatalf("Expected error for invalid redirect URI")
	}
	resp.Close()
}

// TestAuthorizeRequestClientWithEmptyRedirectURI tests a client with empty redirect URI
func TestAuthorizeRequestClientWithEmptyRedirectURI(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	testStorage := NewTestingStorage()
	server := NewServer(sconfig, testStorage)

	testStorage.clients["no-redirect"] = &DefaultClient{
		Id:     "no-redirect",
		Secret: "secret",
		// empty RedirectUri
	}

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "no-redirect")
	req.Form.Set("state", "a")

	ar := server.HandleAuthorizeRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request for client with empty redirect URI")
	}
	if !resp.IsError {
		t.Fatalf("Expected error")
	}
	if resp.ErrorId != E_UNAUTHORIZED_CLIENT {
		t.Fatalf("Expected unauthorized_client, got %s", resp.ErrorId)
	}
	resp.Close()
}

// =============================================================================
// Info Request Error Paths
// =============================================================================

// TestInfoRequestNoBearer tests info request without bearer token
func TestInfoRequestNoBearer(t *testing.T) {
	sconfig := NewServerConfig()
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/info", nil)
	// No bearer token

	ir := server.HandleInfoRequest(resp, req)
	if ir != nil {
		t.Fatalf("Should not return info request without bearer token")
	}
	if !resp.IsError {
		t.Fatalf("Expected error")
	}
	if resp.ErrorId != E_INVALID_REQUEST {
		t.Fatalf("Expected invalid_request, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestInfoRequestNonexistentToken tests info with a token that doesn't exist
func TestInfoRequestNonexistentToken(t *testing.T) {
	sconfig := NewServerConfig()
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/info", nil)
	req.Header.Set("Authorization", "Bearer nonexistent-token")

	ir := server.HandleInfoRequest(resp, req)
	if ir != nil {
		t.Fatalf("Should not return info request for nonexistent token")
	}
	if !resp.IsError {
		t.Fatalf("Expected error")
	}
	if resp.ErrorId != E_INVALID_REQUEST {
		t.Fatalf("Expected invalid_request, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestInfoRequestExpiredToken tests info with an expired access token
func TestInfoRequestExpiredToken(t *testing.T) {
	sconfig := NewServerConfig()
	testStorage := NewTestingStorage()
	server := NewServer(sconfig, testStorage)

	// Create an expired token
	testStorage.SaveAccess(&AccessData{
		Client:      testStorage.clients["1234"],
		AccessToken: "expired-access",
		ExpiresIn:   1,
		CreatedAt:   time.Now().Add(-time.Hour),
		RedirectUri: "http://localhost:14000/appauth",
	})

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/info", nil)
	req.Header.Set("Authorization", "Bearer expired-access")

	ir := server.HandleInfoRequest(resp, req)
	if ir != nil {
		t.Fatalf("Should not return info request for expired token")
	}
	if !resp.IsError {
		t.Fatalf("Expected error for expired token")
	}
	if resp.ErrorId != E_INVALID_GRANT {
		t.Fatalf("Expected invalid_grant, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestInfoRequestWithRefreshTokenAndScope tests info response includes refresh token and scope
func TestInfoRequestWithRefreshTokenAndScope(t *testing.T) {
	sconfig := NewServerConfig()
	testStorage := NewTestingStorage()
	server := NewServer(sconfig, testStorage)

	testStorage.SaveAccess(&AccessData{
		Client:       testStorage.clients["1234"],
		AccessToken:  "rich-token",
		RefreshToken: "rich-refresh",
		ExpiresIn:    3600,
		CreatedAt:    time.Now(),
		Scope:        "read write admin",
		RedirectUri:  "http://localhost:14000/appauth",
	})

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/info", nil)
	req.Header.Set("Authorization", "Bearer rich-token")

	if ir := server.HandleInfoRequest(resp, req); ir != nil {
		server.FinishInfoRequest(resp, req, ir)
	}

	if resp.IsError {
		t.Fatalf("Error: %v", resp.InternalError)
	}
	if resp.Output["refresh_token"] != "rich-refresh" {
		t.Fatalf("Expected refresh_token 'rich-refresh', got %v", resp.Output["refresh_token"])
	}
	if resp.Output["scope"] != "read write admin" {
		t.Fatalf("Expected scope 'read write admin', got %v", resp.Output["scope"])
	}
	resp.Close()
}

// TestInfoFinishAlreadyError tests FinishInfoRequest when response already has error
func TestInfoFinishAlreadyError(t *testing.T) {
	sconfig := NewServerConfig()
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	resp.SetError(E_SERVER_ERROR, "pre-existing")

	ir := &InfoRequest{
		Code: "anything",
		AccessData: &AccessData{
			Client:      &DefaultClient{Id: "1234"},
			AccessToken: "x",
			ExpiresIn:   3600,
			CreatedAt:   time.Now(),
		},
	}

	req, _ := http.NewRequest("GET", "http://localhost:14000/info", nil)
	server.FinishInfoRequest(resp, req, ir)

	// Should not have set output data
	if _, ok := resp.Output["client_id"]; ok {
		t.Fatalf("Should not set output when already an error")
	}
	resp.Close()
}

// =============================================================================
// OutputJSON E2E Integration Tests
// =============================================================================

// TestOutputJSONWithAuthorizationCodeFlow tests JSON output for a full auth code flow
func TestOutputJSONWithAuthorizationCodeFlow(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGen = &TestingAccessTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "9999")
	req.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp, req, ar)
	}

	// Write response through OutputJSON
	w := httptest.NewRecorder()
	err := OutputJSON(resp, w, req)
	if err != nil {
		t.Fatalf("OutputJSON error: %v", err)
	}

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Expected application/json, got %s", ct)
	}

	// Verify cache control headers
	if cc := w.Header().Get("Cache-Control"); cc == "" {
		t.Fatalf("Expected Cache-Control header")
	}
	if p := w.Header().Get("Pragma"); p != "no-cache" {
		t.Fatalf("Expected Pragma: no-cache, got %s", p)
	}

	var output map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &output); err != nil {
		t.Fatalf("Could not parse JSON: %v", err)
	}
	if output["access_token"] != "1" {
		t.Fatalf("Expected access_token '1', got %v", output["access_token"])
	}
	if output["token_type"] != "Bearer" {
		t.Fatalf("Expected token_type 'Bearer', got %v", output["token_type"])
	}
	resp.Close()
}

// TestOutputJSONWithErrorResponse tests JSON output for error responses
func TestOutputJSONWithErrorResponse(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	resp.ErrorStatusCode = 400
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	// No auth - will cause error
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "9999")
	req.PostForm = make(url.Values)

	server.HandleAccessRequest(resp, req)

	w := httptest.NewRecorder()
	err := OutputJSON(resp, w, req)
	if err != nil {
		t.Fatalf("OutputJSON error: %v", err)
	}

	if w.Code != 400 {
		t.Fatalf("Expected 400, got %d", w.Code)
	}

	var output map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &output); err != nil {
		t.Fatalf("Could not parse JSON: %v", err)
	}
	if output["error"] == nil {
		t.Fatalf("Expected error field in output")
	}
	resp.Close()
}

// TestOutputJSONWithRedirectResponse tests JSON output for redirect (authorize) responses
func TestOutputJSONWithRedirectResponse(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	server := NewServer(sconfig, NewTestingStorage())
	server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "xyz")

	if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAuthorizeRequest(resp, req, ar)
	}

	w := httptest.NewRecorder()
	err := OutputJSON(resp, w, req)
	if err != nil {
		t.Fatalf("OutputJSON error: %v", err)
	}

	if w.Code != 302 {
		t.Fatalf("Expected 302, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if location == "" {
		t.Fatalf("Expected Location header")
	}

	// Parse the redirect URL and verify parameters
	parsedURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("Could not parse redirect URL: %v", err)
	}
	if parsedURL.Query().Get("code") == "" {
		t.Fatalf("Expected code in redirect URL")
	}
	if parsedURL.Query().Get("state") != "xyz" {
		t.Fatalf("Expected state 'xyz' in redirect URL, got %s", parsedURL.Query().Get("state"))
	}
	resp.Close()
}

// TestOutputJSONCustomContentType tests that existing Content-Type is preserved
func TestOutputJSONCustomContentType(t *testing.T) {
	resp := NewResponse(NewTestingStorage())
	resp.Output["test"] = "value"

	w := httptest.NewRecorder()
	w.Header().Set("Content-Type", "application/custom+json")

	req, _ := http.NewRequest("GET", "http://localhost:14000/test", nil)
	err := OutputJSON(resp, w, req)
	if err != nil {
		t.Fatalf("OutputJSON error: %v", err)
	}

	if ct := w.Header().Get("Content-Type"); ct != "application/custom+json" {
		t.Fatalf("Expected custom content type preserved, got %s", ct)
	}
	resp.Close()
}

// =============================================================================
// Default Token Generator Tests
// =============================================================================

// TestDefaultAuthorizeTokenGen tests the default authorize token generator
func TestDefaultAuthorizeTokenGen(t *testing.T) {
	gen := &AuthorizeTokenGenDefault{}
	data := &AuthorizeData{
		Client:    &DefaultClient{Id: "test"},
		ExpiresIn: 3600,
		CreatedAt: time.Now(),
	}

	token1, err := gen.GenerateAuthorizeToken(data)
	if err != nil {
		t.Fatalf("Error generating token: %v", err)
	}
	if token1 == "" {
		t.Fatalf("Expected non-empty token")
	}

	token2, err := gen.GenerateAuthorizeToken(data)
	if err != nil {
		t.Fatalf("Error generating second token: %v", err)
	}
	if token1 == token2 {
		t.Fatalf("Tokens should be unique")
	}
}

// TestDefaultAccessTokenGen tests the default access token generator
func TestDefaultAccessTokenGen(t *testing.T) {
	gen := &AccessTokenGenDefault{}
	data := &AccessData{
		Client:    &DefaultClient{Id: "test"},
		ExpiresIn: 3600,
		CreatedAt: time.Now(),
	}

	// Without refresh token
	access1, refresh1, err := gen.GenerateAccessToken(data, false)
	if err != nil {
		t.Fatalf("Error generating token: %v", err)
	}
	if access1 == "" {
		t.Fatalf("Expected non-empty access token")
	}
	if refresh1 != "" {
		t.Fatalf("Expected empty refresh token when not requested")
	}

	// With refresh token
	access2, refresh2, err := gen.GenerateAccessToken(data, true)
	if err != nil {
		t.Fatalf("Error generating token: %v", err)
	}
	if access2 == "" {
		t.Fatalf("Expected non-empty access token")
	}
	if refresh2 == "" {
		t.Fatalf("Expected non-empty refresh token")
	}
	if access1 == access2 {
		t.Fatalf("Access tokens should be unique")
	}
}

// =============================================================================
// Response Edge Cases
// =============================================================================

// TestResponseGetRedirectUrlNonRedirect tests GetRedirectUrl on non-redirect response
func TestResponseGetRedirectUrlNonRedirect(t *testing.T) {
	resp := &Response{
		Type: DATA,
	}
	_, err := resp.GetRedirectUrl()
	if err == nil {
		t.Fatalf("Expected error for non-redirect response")
	}
}

// TestResponseSetErrorUri tests SetErrorUri with custom URI and state
func TestResponseSetErrorUri(t *testing.T) {
	resp := NewResponse(NewTestingStorage())
	resp.ErrorStatusCode = 400
	resp.SetErrorUri("custom_error", "Custom description", "http://error.example.com", "mystate")

	if !resp.IsError {
		t.Fatalf("Expected error state")
	}
	if resp.ErrorId != "custom_error" {
		t.Fatalf("Expected error id 'custom_error', got %s", resp.ErrorId)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("Expected status code 400, got %d", resp.StatusCode)
	}
	if resp.StatusText != "Custom description" {
		t.Fatalf("Expected status text 'Custom description', got %s", resp.StatusText)
	}
	if resp.Output["error_uri"] != "http://error.example.com" {
		t.Fatalf("Expected error_uri in output, got %v", resp.Output["error_uri"])
	}
	if resp.Output["state"] != "mystate" {
		t.Fatalf("Expected state in output, got %v", resp.Output["state"])
	}
	resp.Close()
}

// TestResponseSetErrorUriDefaultDescription tests that default description is used when blank
func TestResponseSetErrorUriDefaultDescription(t *testing.T) {
	resp := NewResponse(NewTestingStorage())
	resp.SetError(E_INVALID_REQUEST, "")

	if resp.Output["error_description"] != deferror.Get(E_INVALID_REQUEST) {
		t.Fatalf("Expected default error description, got %v", resp.Output["error_description"])
	}
	resp.Close()
}

// TestResponseClose tests the Close method
func TestResponseClose(t *testing.T) {
	storage := NewTestingStorage()
	resp := NewResponse(storage)
	// Should not panic
	resp.Close()
}

// =============================================================================
// Misc Coverage Tests
// =============================================================================

// TestFirstUriWithSeparator tests FirstUri with a separator
func TestFirstUriWithSeparator(t *testing.T) {
	// Single URI with separator
	uri := FirstUri("http://example.com", ";")
	if uri != "http://example.com" {
		t.Fatalf("Expected http://example.com, got %s", uri)
	}

	// Multiple URIs with separator
	uri = FirstUri("http://first.com;http://second.com;http://third.com", ";")
	if uri != "http://first.com" {
		t.Fatalf("Expected http://first.com, got %s", uri)
	}

	// Empty string with separator
	uri = FirstUri("", ";")
	if uri != "" {
		t.Fatalf("Expected empty string, got %s", uri)
	}

	// No separator
	uri = FirstUri("http://example.com", "")
	if uri != "http://example.com" {
		t.Fatalf("Expected http://example.com, got %s", uri)
	}
}

// TestAccessDataExpiration tests the AccessData expiration helpers
func TestAccessDataExpiration(t *testing.T) {
	now := time.Now()

	// Not expired
	ad := &AccessData{
		CreatedAt: now,
		ExpiresIn: 3600,
	}
	if ad.IsExpired() {
		t.Fatalf("Token should not be expired")
	}
	if ad.IsExpiredAt(now.Add(time.Minute)) {
		t.Fatalf("Token should not be expired at 1 minute")
	}

	expectedExpireAt := now.Add(3600 * time.Second)
	if !ad.ExpireAt().Equal(expectedExpireAt) {
		t.Fatalf("Expected expiry at %v, got %v", expectedExpireAt, ad.ExpireAt())
	}

	// Expired
	adExpired := &AccessData{
		CreatedAt: now.Add(-2 * time.Hour),
		ExpiresIn: 3600,
	}
	if !adExpired.IsExpired() {
		t.Fatalf("Token should be expired")
	}
	if !adExpired.IsExpiredAt(now) {
		t.Fatalf("Token should be expired at now")
	}
}

// TestAuthorizeDataExpiration tests the AuthorizeData expiration helpers
func TestAuthorizeDataExpiration(t *testing.T) {
	now := time.Now()

	// Not expired
	ad := &AuthorizeData{
		CreatedAt: now,
		ExpiresIn: 300,
	}
	if ad.IsExpired() {
		t.Fatalf("Auth data should not be expired")
	}
	if ad.IsExpiredAt(now.Add(time.Minute)) {
		t.Fatalf("Auth data should not be expired at 1 minute")
	}

	expectedExpireAt := now.Add(300 * time.Second)
	if !ad.ExpireAt().Equal(expectedExpireAt) {
		t.Fatalf("Expected expiry at %v, got %v", expectedExpireAt, ad.ExpireAt())
	}

	// Expired
	adExpired := &AuthorizeData{
		CreatedAt: now.Add(-time.Hour),
		ExpiresIn: 300,
	}
	if !adExpired.IsExpired() {
		t.Fatalf("Auth data should be expired")
	}
}

// TestDefaultClientCopyFrom tests the CopyFrom method
func TestDefaultClientCopyFrom(t *testing.T) {
	source := &DefaultClient{
		Id:          "source-id",
		Secret:      "source-secret",
		RedirectUri: "http://source.example.com",
		UserData:    map[string]string{"key": "value"},
	}

	dest := &DefaultClient{}
	dest.CopyFrom(source)

	if dest.GetId() != "source-id" {
		t.Fatalf("Expected id 'source-id', got %s", dest.GetId())
	}
	if dest.GetSecret() != "source-secret" {
		t.Fatalf("Expected secret 'source-secret', got %s", dest.GetSecret())
	}
	if dest.GetRedirectUri() != "http://source.example.com" {
		t.Fatalf("Expected redirect uri 'http://source.example.com', got %s", dest.GetRedirectUri())
	}
	if dest.GetUserData() == nil {
		t.Fatalf("Expected non-nil user data")
	}
}

// TestDefaultClientSecretMatches tests the ClientSecretMatches method on DefaultClient
func TestDefaultClientSecretMatches(t *testing.T) {
	client := &DefaultClient{
		Id:     "test",
		Secret: "mysecret",
	}

	if !client.ClientSecretMatches("mysecret") {
		t.Fatalf("Expected secret to match")
	}
	if client.ClientSecretMatches("wrongsecret") {
		t.Fatalf("Expected secret not to match")
	}
	if client.ClientSecretMatches("") {
		t.Fatalf("Expected empty secret not to match")
	}
}

// TestCheckClientSecretPublicClient tests CheckClientSecret for a public client
func TestCheckClientSecretPublicClient(t *testing.T) {
	client := &DefaultClient{
		Id:     "public",
		Secret: "",
	}

	if !CheckClientSecret(client, "") {
		t.Fatalf("Public client should accept empty secret")
	}
	if CheckClientSecret(client, "notempty") {
		t.Fatalf("Public client should reject non-empty secret")
	}
}

// TestAllowedAccessTypeExists tests the AllowedAccessType.Exists method
func TestAllowedAccessTypeExists(t *testing.T) {
	allowed := AllowedAccessType{AUTHORIZATION_CODE, REFRESH_TOKEN}

	if !allowed.Exists(AUTHORIZATION_CODE) {
		t.Fatalf("Should find AUTHORIZATION_CODE")
	}
	if !allowed.Exists(REFRESH_TOKEN) {
		t.Fatalf("Should find REFRESH_TOKEN")
	}
	if allowed.Exists(PASSWORD) {
		t.Fatalf("Should not find PASSWORD")
	}
	if allowed.Exists(CLIENT_CREDENTIALS) {
		t.Fatalf("Should not find CLIENT_CREDENTIALS")
	}
}

// TestAllowedAuthorizeTypeExists tests the AllowedAuthorizeType.Exists method
func TestAllowedAuthorizeTypeExists(t *testing.T) {
	allowed := AllowedAuthorizeType{CODE}

	if !allowed.Exists(CODE) {
		t.Fatalf("Should find CODE")
	}
	if allowed.Exists(TOKEN) {
		t.Fatalf("Should not find TOKEN")
	}
}

// TestNewServerConfig tests default server configuration
func TestNewServerConfig(t *testing.T) {
	config := NewServerConfig()

	if config.AuthorizationExpiration != 250 {
		t.Fatalf("Expected AuthorizationExpiration 250, got %d", config.AuthorizationExpiration)
	}
	if config.AccessExpiration != 3600 {
		t.Fatalf("Expected AccessExpiration 3600, got %d", config.AccessExpiration)
	}
	if config.TokenType != "Bearer" {
		t.Fatalf("Expected TokenType 'Bearer', got %s", config.TokenType)
	}
	if config.ErrorStatusCode != 200 {
		t.Fatalf("Expected ErrorStatusCode 200, got %d", config.ErrorStatusCode)
	}
	if config.AllowClientSecretInParams {
		t.Fatalf("AllowClientSecretInParams should be false by default")
	}
	if config.AllowGetAccessRequest {
		t.Fatalf("AllowGetAccessRequest should be false by default")
	}
	if config.RetainTokenAfterRefresh {
		t.Fatalf("RetainTokenAfterRefresh should be false by default")
	}
}

// TestAccessAuthCodePKCEUnsupportedMethod tests PKCE with an unsupported transform method in storage
func TestAccessAuthCodePKCEUnsupportedMethod(t *testing.T) {
	testStorage := NewTestingStorage()
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, testStorage)
	server.AccessTokenGen = &TestingAccessTokenGen{}

	// Save auth code with unsupported PKCE method
	testStorage.SaveAuthorize(&AuthorizeData{
		Client:              testStorage.clients["public-client"],
		Code:                "pkce-unsupported-code",
		ExpiresIn:           3600,
		CreatedAt:           time.Now(),
		RedirectUri:         "http://localhost:14000/appauth",
		CodeChallenge:       "12345678901234567890123456789012345678901234567890",
		CodeChallengeMethod: "RS256", // unsupported
	})

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("public-client", "")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "pkce-unsupported-code")
	req.Form.Set("code_verifier", "12345678901234567890123456789012345678901234567890")
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request for unsupported PKCE method")
	}
	if !resp.IsError {
		t.Fatalf("Expected error")
	}
	if resp.ErrorId != E_INVALID_REQUEST {
		t.Fatalf("Expected invalid_request, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestAccessAuthCodePKCEInvalidVerifierFormat tests PKCE with an invalid code_verifier format
func TestAccessAuthCodePKCEInvalidVerifierFormat(t *testing.T) {
	testStorage := NewTestingStorage()
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, testStorage)
	server.AccessTokenGen = &TestingAccessTokenGen{}

	testStorage.SaveAuthorize(&AuthorizeData{
		Client:              testStorage.clients["public-client"],
		Code:                "pkce-bad-verifier-code",
		ExpiresIn:           3600,
		CreatedAt:           time.Now(),
		RedirectUri:         "http://localhost:14000/appauth",
		CodeChallenge:       "12345678901234567890123456789012345678901234567890",
		CodeChallengeMethod: "plain",
	})

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("public-client", "")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "pkce-bad-verifier-code")
	req.Form.Set("code_verifier", "too-short!") // invalid format (too short, has special chars)
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request for invalid verifier format")
	}
	if !resp.IsError {
		t.Fatalf("Expected error")
	}
	if resp.ErrorId != E_INVALID_REQUEST {
		t.Fatalf("Expected invalid_request, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestUriValidationErrorString tests the UriValidationError.Error() method
func TestUriValidationErrorString(t *testing.T) {
	err := newUriValidationError("test error", "http://base.com", "http://redirect.com")
	expected := "test error: http://base.com / http://redirect.com"
	if err.Error() != expected {
		t.Fatalf("Expected '%s', got '%s'", expected, err.Error())
	}
}

// TestAccessRequestNonexistentClient tests access request with a nonexistent client
func TestAccessRequestNonexistentClient(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("nonexistent-client", "secret")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "9999")
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request for nonexistent client")
	}
	if !resp.IsError {
		t.Fatalf("Expected error")
	}
	if resp.ErrorId != E_UNAUTHORIZED_CLIENT {
		t.Fatalf("Expected unauthorized_client, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestAccessClientWithEmptyRedirectURI tests access request where client has empty redirect URI
func TestAccessClientWithEmptyRedirectURI(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{PASSWORD}
	testStorage := NewTestingStorage()
	server := NewServer(sconfig, testStorage)

	testStorage.clients["no-redir"] = &DefaultClient{
		Id:     "no-redir",
		Secret: "secret",
		// empty RedirectUri
	}

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("no-redir", "secret")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(PASSWORD))
	req.Form.Set("username", "user")
	req.Form.Set("password", "pass")
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatalf("Should not return request for client with empty redirect URI")
	}
	if !resp.IsError {
		t.Fatalf("Expected error")
	}
	if resp.ErrorId != E_UNAUTHORIZED_CLIENT {
		t.Fatalf("Expected unauthorized_client, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestE2EAuthorizationCodeFlowWithOutputJSON tests the complete flow with actual HTTP output
func TestE2EAuthorizationCodeFlowWithOutputJSON(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, NewTestingStorage())
	server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}
	server.AccessTokenGen = &TestingAccessTokenGen{}

	// Step 1: Authorization request with full HTTP simulation
	authResp := server.NewResponse()
	authReq, _ := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	authReq.Form = make(url.Values)
	authReq.Form.Set("response_type", string(CODE))
	authReq.Form.Set("client_id", "1234")
	authReq.Form.Set("state", "teststate")

	if ar := server.HandleAuthorizeRequest(authResp, authReq); ar != nil {
		ar.Authorized = true
		server.FinishAuthorizeRequest(authResp, authReq, ar)
	}

	w1 := httptest.NewRecorder()
	if err := OutputJSON(authResp, w1, authReq); err != nil {
		t.Fatalf("OutputJSON error: %v", err)
	}
	if w1.Code != 302 {
		t.Fatalf("Expected 302 redirect, got %d", w1.Code)
	}

	location := w1.Header().Get("Location")
	parsedURL, _ := url.Parse(location)
	code := parsedURL.Query().Get("code")
	if code == "" {
		t.Fatalf("No code in redirect URL")
	}
	authResp.Close()

	// Step 2: Token exchange with full HTTP simulation
	tokenResp := server.NewResponse()
	tokenReq, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	tokenReq.SetBasicAuth("1234", "aabbccdd")
	tokenReq.Form = make(url.Values)
	tokenReq.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	tokenReq.Form.Set("code", code)
	tokenReq.Form.Set("redirect_uri", "http://localhost:14000/appauth")
	tokenReq.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(tokenResp, tokenReq); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(tokenResp, tokenReq, ar)
	}

	w2 := httptest.NewRecorder()
	if err := OutputJSON(tokenResp, w2, tokenReq); err != nil {
		t.Fatalf("OutputJSON error: %v", err)
	}
	if w2.Code != 200 {
		t.Fatalf("Expected 200, got %d", w2.Code)
	}

	var tokenOutput map[string]interface{}
	if err := json.Unmarshal(w2.Body.Bytes(), &tokenOutput); err != nil {
		t.Fatalf("Could not parse token response: %v", err)
	}
	if tokenOutput["access_token"] == nil {
		t.Fatalf("No access_token in response")
	}
	if tokenOutput["refresh_token"] == nil {
		t.Fatalf("No refresh_token in response")
	}
	if tokenOutput["token_type"] != "Bearer" {
		t.Fatalf("Expected Bearer token_type")
	}
	tokenResp.Close()
}
