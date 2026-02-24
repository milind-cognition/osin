package osin

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// =============================================================================
// Error-returning storage for testing storage failure paths
// =============================================================================

type errorStorage struct {
	*TestingStorage
	getClientErr     error
	loadAuthorizeErr error
	loadAccessErr    error
	saveAccessErr    error
	saveAuthorizeErr error
}

func newErrorStorage() *errorStorage {
	return &errorStorage{TestingStorage: NewTestingStorage()}
}

func (s *errorStorage) Clone() Storage { return s }
func (s *errorStorage) Close()         {}

func (s *errorStorage) GetClient(id string) (Client, error) {
	if s.getClientErr != nil {
		return nil, s.getClientErr
	}
	return s.TestingStorage.GetClient(id)
}

func (s *errorStorage) LoadAuthorize(code string) (*AuthorizeData, error) {
	if s.loadAuthorizeErr != nil {
		return nil, s.loadAuthorizeErr
	}
	return s.TestingStorage.LoadAuthorize(code)
}

func (s *errorStorage) LoadAccess(code string) (*AccessData, error) {
	if s.loadAccessErr != nil {
		return nil, s.loadAccessErr
	}
	return s.TestingStorage.LoadAccess(code)
}

func (s *errorStorage) SaveAccess(data *AccessData) error {
	if s.saveAccessErr != nil {
		return s.saveAccessErr
	}
	return s.TestingStorage.SaveAccess(data)
}

func (s *errorStorage) SaveAuthorize(data *AuthorizeData) error {
	if s.saveAuthorizeErr != nil {
		return s.saveAuthorizeErr
	}
	return s.TestingStorage.SaveAuthorize(data)
}

func (s *errorStorage) LoadRefresh(code string) (*AccessData, error) {
	return s.TestingStorage.LoadRefresh(code)
}

func (s *errorStorage) RemoveAuthorize(code string) error {
	return s.TestingStorage.RemoveAuthorize(code)
}

func (s *errorStorage) RemoveAccess(code string) error {
	return s.TestingStorage.RemoveAccess(code)
}

func (s *errorStorage) RemoveRefresh(code string) error {
	return s.TestingStorage.RemoveRefresh(code)
}

// Error-returning token generator for testing token generation failures
type errorTokenGen struct{}

func (g *errorTokenGen) GenerateAccessToken(data *AccessData, generaterefresh bool) (string, string, error) {
	return "", "", errors.New("token generation failed")
}

// Error-returning authorize token generator
type errorAuthorizeTokenGen struct{}

func (g *errorAuthorizeTokenGen) GenerateAuthorizeToken(data *AuthorizeData) (string, error) {
	return "", errors.New("authorize token generation failed")
}

// =============================================================================
// access.go: HandleAccessRequest — ParseForm error (lines 127-130)
// =============================================================================

// TestAccessRequestParseFormError tests that a malformed request body triggers a parse error.
func TestAccessRequestParseFormError(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	// Create a request with an invalid body that causes ParseForm to fail
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth?%gh&%ij", nil)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatal("Expected nil access request on parse form error")
	}
	if !resp.IsError {
		t.Fatal("Expected error response")
	}
	if resp.ErrorId != E_INVALID_REQUEST {
		t.Fatalf("Expected invalid_request, got %s", resp.ErrorId)
	}
	resp.Close()
}

// =============================================================================
// access.go: handleAuthorizationCodeRequest — AuthorizeData nil client (line 192-195)
// =============================================================================

// TestAccessAuthCodeAuthorizeDataNilClient tests that an authorization code with nil client
// in the authorize data returns an error.
func TestAccessAuthCodeAuthorizeDataNilClient(t *testing.T) {
	storage := NewTestingStorage()
	// Create authorize data with nil client
	storage.authorize["nilclient"] = &AuthorizeData{
		Client:      nil,
		Code:        "nilclient",
		ExpiresIn:   3600,
		CreatedAt:   time.Now(),
		RedirectUri: "http://localhost:14000/appauth",
	}

	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, storage)
	server.AccessTokenGen = &TestingAccessTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "nilclient")
	req.Form.Set("redirect_uri", "http://localhost:14000/appauth")
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatal("Expected nil for authorize data with nil client")
	}
	if !resp.IsError {
		t.Fatal("Expected error")
	}
	if resp.ErrorId != E_UNAUTHORIZED_CLIENT {
		t.Fatalf("Expected unauthorized_client, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestAccessAuthCodeAuthorizeDataEmptyRedirectUri tests that an authorization code
// with an empty redirect URI in the authorize data client returns an error.
func TestAccessAuthCodeAuthorizeDataEmptyRedirectUri(t *testing.T) {
	storage := NewTestingStorage()
	emptyRedirectClient := &DefaultClient{
		Id:          "emptyredirect",
		Secret:      "secret",
		RedirectUri: "",
	}
	storage.clients["emptyredirect"] = emptyRedirectClient
	storage.authorize["emptycode"] = &AuthorizeData{
		Client:      emptyRedirectClient,
		Code:        "emptycode",
		ExpiresIn:   3600,
		CreatedAt:   time.Now(),
		RedirectUri: "http://localhost:14000/appauth",
	}

	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, storage)
	server.AccessTokenGen = &TestingAccessTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("emptyredirect", "secret")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "emptycode")
	req.Form.Set("redirect_uri", "http://localhost:14000/appauth")
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatal("Expected nil for authorize data with empty redirect uri client")
	}
	if !resp.IsError {
		t.Fatal("Expected error")
	}
	if resp.ErrorId != E_UNAUTHORIZED_CLIENT {
		t.Fatalf("Expected unauthorized_client, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestAccessAuthCodeRedirectUriMismatchWithAuthorizeData tests that a redirect URI
// that doesn't match the one stored in authorize data returns an error.
func TestAccessAuthCodeRedirectUriMismatchWithAuthorizeData(t *testing.T) {
	storage := NewTestingStorage()
	// Override the authorize data redirect URI to differ from what we'll send
	storage.authorize["9999"].RedirectUri = "http://localhost:14000/different"

	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, storage)
	server.AccessTokenGen = &TestingAccessTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "9999")
	req.Form.Set("redirect_uri", "http://localhost:14000/appauth")
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatal("Expected nil for redirect URI mismatch")
	}
	if !resp.IsError {
		t.Fatal("Expected error")
	}
	if resp.ErrorId != E_INVALID_REQUEST {
		t.Fatalf("Expected invalid_request, got %s", resp.ErrorId)
	}
	resp.Close()
}

// =============================================================================
// access.go: handleRefreshTokenRequest — AccessData nil/client nil/empty redirect
// (lines 321-332)
// =============================================================================

// TestRefreshTokenAccessDataNilClient tests refresh token path when access data has nil client.
func TestRefreshTokenAccessDataNilClient(t *testing.T) {
	storage := NewTestingStorage()
	storage.access["nilclient-access"] = &AccessData{
		Client:       nil,
		AccessToken:  "nilclient-access",
		RefreshToken: "nilclient-refresh",
		ExpiresIn:    3600,
		CreatedAt:    time.Now(),
	}
	storage.refresh["nilclient-refresh"] = "nilclient-access"

	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{REFRESH_TOKEN}
	server := NewServer(sconfig, storage)
	server.AccessTokenGen = &TestingAccessTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(REFRESH_TOKEN))
	req.Form.Set("refresh_token", "nilclient-refresh")
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatal("Expected nil for refresh token with nil client in access data")
	}
	if !resp.IsError {
		t.Fatal("Expected error")
	}
	if resp.ErrorId != E_UNAUTHORIZED_CLIENT {
		t.Fatalf("Expected unauthorized_client, got %s", resp.ErrorId)
	}
	resp.Close()
}

// TestRefreshTokenAccessDataEmptyRedirectUri tests refresh token when access data
// client has empty redirect URI.
func TestRefreshTokenAccessDataEmptyRedirectUri(t *testing.T) {
	storage := NewTestingStorage()
	emptyClient := &DefaultClient{
		Id:          "emptyredirect2",
		Secret:      "secret2",
		RedirectUri: "",
	}
	storage.clients["emptyredirect2"] = emptyClient
	storage.access["emptyredirect-access"] = &AccessData{
		Client:       emptyClient,
		AccessToken:  "emptyredirect-access",
		RefreshToken: "emptyredirect-refresh",
		ExpiresIn:    3600,
		CreatedAt:    time.Now(),
	}
	storage.refresh["emptyredirect-refresh"] = "emptyredirect-access"

	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{REFRESH_TOKEN}
	server := NewServer(sconfig, storage)
	server.AccessTokenGen = &TestingAccessTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("emptyredirect2", "secret2")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(REFRESH_TOKEN))
	req.Form.Set("refresh_token", "emptyredirect-refresh")
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatal("Expected nil for refresh token with empty redirect client")
	}
	if !resp.IsError {
		t.Fatal("Expected error")
	}
	if resp.ErrorId != E_UNAUTHORIZED_CLIENT {
		t.Fatalf("Expected unauthorized_client, got %s", resp.ErrorId)
	}
	resp.Close()
}

// =============================================================================
// access.go: FinishAccessRequest — token generation error (lines 483-486)
// =============================================================================

// TestFinishAccessRequestTokenGenError tests that FinishAccessRequest returns
// a server error when token generation fails.
func TestFinishAccessRequestTokenGenError(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{CLIENT_CREDENTIALS}
	server := NewServer(sconfig, NewTestingStorage())
	server.AccessTokenGen = &errorTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(CLIENT_CREDENTIALS))
	req.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp, req, ar)
	}

	if !resp.IsError {
		t.Fatal("Expected error when token generation fails")
	}
	if resp.ErrorId != E_SERVER_ERROR {
		t.Fatalf("Expected server_error, got %s", resp.ErrorId)
	}
	resp.Close()
}

// =============================================================================
// access.go: FinishAccessRequest — SaveAccess error (lines 492-495)
// =============================================================================

// TestFinishAccessRequestSaveAccessError tests that FinishAccessRequest returns
// a server error when saving the access token fails.
func TestFinishAccessRequestSaveAccessError(t *testing.T) {
	es := newErrorStorage()
	es.saveAccessErr = errors.New("storage write failed")

	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{CLIENT_CREDENTIALS}
	server := NewServer(sconfig, es)
	server.AccessTokenGen = &TestingAccessTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(CLIENT_CREDENTIALS))
	req.PostForm = make(url.Values)

	if ar := server.HandleAccessRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAccessRequest(resp, req, ar)
	}

	if !resp.IsError {
		t.Fatal("Expected error when save access fails")
	}
	if resp.ErrorId != E_SERVER_ERROR {
		t.Fatalf("Expected server_error, got %s", resp.ErrorId)
	}
	resp.Close()
}

// =============================================================================
// access.go: getClient — non-ErrNotFound storage error (lines 535-538)
// and nil client (lines 539-542)
// =============================================================================

// TestGetClientStorageError tests that a non-ErrNotFound storage error
// returns a server error.
func TestGetClientStorageError(t *testing.T) {
	es := newErrorStorage()
	es.getClientErr = errors.New("connection refused")

	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{CLIENT_CREDENTIALS}
	server := NewServer(sconfig, es)
	server.AccessTokenGen = &TestingAccessTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(CLIENT_CREDENTIALS))
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatal("Expected nil when storage returns an error")
	}
	if !resp.IsError {
		t.Fatal("Expected error")
	}
	if resp.ErrorId != E_SERVER_ERROR {
		t.Fatalf("Expected server_error, got %s", resp.ErrorId)
	}
	resp.Close()
}

// nilClientStorage returns nil client without error
type nilClientStorage struct {
	*TestingStorage
}

func (s *nilClientStorage) Clone() Storage                              { return s }
func (s *nilClientStorage) Close()                                      {}
func (s *nilClientStorage) GetClient(id string) (Client, error)         { return nil, nil }
func (s *nilClientStorage) SaveAuthorize(data *AuthorizeData) error     { return nil }
func (s *nilClientStorage) LoadAuthorize(code string) (*AuthorizeData, error) {
	return s.TestingStorage.LoadAuthorize(code)
}
func (s *nilClientStorage) RemoveAuthorize(code string) error           { return nil }
func (s *nilClientStorage) SaveAccess(data *AccessData) error           { return nil }
func (s *nilClientStorage) LoadAccess(code string) (*AccessData, error) { return nil, nil }
func (s *nilClientStorage) RemoveAccess(code string) error              { return nil }
func (s *nilClientStorage) LoadRefresh(code string) (*AccessData, error) {
	return s.TestingStorage.LoadRefresh(code)
}
func (s *nilClientStorage) RemoveRefresh(code string) error { return nil }

// TestGetClientNilClient tests that a nil client from storage returns unauthorized_client error.
func TestGetClientNilClient(t *testing.T) {
	ns := &nilClientStorage{TestingStorage: NewTestingStorage()}

	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{CLIENT_CREDENTIALS}
	server := NewServer(sconfig, ns)
	server.AccessTokenGen = &TestingAccessTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(CLIENT_CREDENTIALS))
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatal("Expected nil when storage returns nil client")
	}
	if !resp.IsError {
		t.Fatal("Expected error")
	}
	if resp.ErrorId != E_UNAUTHORIZED_CLIENT {
		t.Fatalf("Expected unauthorized_client, got %s", resp.ErrorId)
	}
	resp.Close()
}

// =============================================================================
// authorize.go: HandleAuthorizeRequest — URL unescape error (lines 111-115)
// =============================================================================

// TestAuthorizeRequestInvalidRedirectUriEncoding tests that a malformed percent-encoded
// redirect_uri returns an error.
func TestAuthorizeRequestInvalidRedirectUriEncoding(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")
	req.Form.Set("redirect_uri", "%gh") // invalid percent-encoding

	ar := server.HandleAuthorizeRequest(resp, req)
	if ar != nil {
		t.Fatal("Expected nil for invalid redirect_uri encoding")
	}
	if !resp.IsError {
		t.Fatal("Expected error")
	}
	if resp.ErrorId != E_INVALID_REQUEST {
		t.Fatalf("Expected invalid_request, got %s", resp.ErrorId)
	}
	resp.Close()
}

// =============================================================================
// authorize.go: HandleAuthorizeRequest — non-ErrNotFound GetClient error (lines 131-135)
// =============================================================================

// TestAuthorizeRequestStorageError tests that a non-ErrNotFound storage error
// returns a server error.
func TestAuthorizeRequestStorageError(t *testing.T) {
	es := newErrorStorage()
	es.getClientErr = errors.New("database connection lost")

	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	server := NewServer(sconfig, es)

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")

	ar := server.HandleAuthorizeRequest(resp, req)
	if ar != nil {
		t.Fatal("Expected nil for storage error")
	}
	if !resp.IsError {
		t.Fatal("Expected error")
	}
	if resp.ErrorId != E_SERVER_ERROR {
		t.Fatalf("Expected server_error, got %s", resp.ErrorId)
	}
	resp.Close()
}

// =============================================================================
// authorize.go: HandleAuthorizeRequest — nil client from storage (lines 136-139)
// =============================================================================

// TestAuthorizeRequestNilClient tests that a nil client from storage returns
// an unauthorized_client error.
func TestAuthorizeRequestNilClient(t *testing.T) {
	ns := &nilClientStorage{TestingStorage: NewTestingStorage()}

	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	server := NewServer(sconfig, ns)

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")

	ar := server.HandleAuthorizeRequest(resp, req)
	if ar != nil {
		t.Fatal("Expected nil for nil client")
	}
	if !resp.IsError {
		t.Fatal("Expected error")
	}
	if resp.ErrorId != E_UNAUTHORIZED_CLIENT {
		t.Fatalf("Expected unauthorized_client, got %s", resp.ErrorId)
	}
	resp.Close()
}

// =============================================================================
// authorize.go: FinishAuthorizeRequest — GenerateAuthorizeToken error (lines 255-259)
// =============================================================================

// TestFinishAuthorizeRequestTokenGenError tests that FinishAuthorizeRequest returns
// a server error when authorization token generation fails.
func TestFinishAuthorizeRequestTokenGenError(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	server := NewServer(sconfig, NewTestingStorage())
	server.AuthorizeTokenGen = &errorAuthorizeTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "teststate")

	if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAuthorizeRequest(resp, req, ar)
	}

	if !resp.IsError {
		t.Fatal("Expected error when token generation fails")
	}
	if resp.ErrorId != E_SERVER_ERROR {
		t.Fatalf("Expected server_error, got %s", resp.ErrorId)
	}
	resp.Close()
}

// =============================================================================
// authorize.go: FinishAuthorizeRequest — SaveAuthorize error (lines 263-267)
// =============================================================================

// TestFinishAuthorizeRequestSaveError tests that FinishAuthorizeRequest returns
// a server error when saving the authorization data fails.
func TestFinishAuthorizeRequestSaveError(t *testing.T) {
	es := newErrorStorage()
	es.saveAuthorizeErr = errors.New("storage save failed")

	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	server := NewServer(sconfig, es)
	server.AuthorizeTokenGen = &TestingAuthorizeTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "1234")
	req.Form.Set("state", "teststate")

	if ar := server.HandleAuthorizeRequest(resp, req); ar != nil {
		ar.Authorized = true
		server.FinishAuthorizeRequest(resp, req, ar)
	}

	if !resp.IsError {
		t.Fatal("Expected error when save authorize fails")
	}
	if resp.ErrorId != E_SERVER_ERROR {
		t.Fatalf("Expected server_error, got %s", resp.ErrorId)
	}
	resp.Close()
}

// =============================================================================
// info.go: HandleInfoRequest — empty bearer code (lines 29-32)
// =============================================================================

// TestInfoRequestEmptyBearerCode tests that a bearer token with an empty code
// returns an error.
func TestInfoRequestEmptyBearerCode(t *testing.T) {
	sconfig := NewServerConfig()
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/info", nil)
	// Set Authorization header but with empty bearer
	req.Form = make(url.Values)
	req.Form.Set("code", "")
	req.Header.Set("Authorization", "Bearer ")

	ir := server.HandleInfoRequest(resp, req)
	if ir != nil {
		t.Fatal("Expected nil for empty bearer code")
	}
	if !resp.IsError {
		t.Fatal("Expected error")
	}
	if resp.ErrorId != E_INVALID_REQUEST {
		t.Fatalf("Expected invalid_request, got %s", resp.ErrorId)
	}
	resp.Close()
}

// =============================================================================
// info.go: HandleInfoRequest — nil client in access data (lines 46-49)
// =============================================================================

// TestInfoRequestAccessDataNilClient tests that an access token whose access data
// has a nil client returns an error.
func TestInfoRequestAccessDataNilClient(t *testing.T) {
	storage := NewTestingStorage()
	storage.access["nilclient-token"] = &AccessData{
		Client:      nil,
		AccessToken: "nilclient-token",
		ExpiresIn:   3600,
		CreatedAt:   time.Now(),
	}

	sconfig := NewServerConfig()
	server := NewServer(sconfig, storage)

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/info", nil)
	req.Header.Set("Authorization", "Bearer nilclient-token")

	ir := server.HandleInfoRequest(resp, req)
	if ir != nil {
		t.Fatal("Expected nil for access data with nil client")
	}
	if !resp.IsError {
		t.Fatal("Expected error")
	}
	if resp.ErrorId != E_UNAUTHORIZED_CLIENT {
		t.Fatalf("Expected unauthorized_client, got %s", resp.ErrorId)
	}
	resp.Close()
}

// =============================================================================
// info.go: HandleInfoRequest — empty redirect URI in client (lines 50-53)
// =============================================================================

// TestInfoRequestAccessDataEmptyRedirectUri tests that an access token whose client
// has an empty redirect URI returns an error.
func TestInfoRequestAccessDataEmptyRedirectUri(t *testing.T) {
	storage := NewTestingStorage()
	emptyClient := &DefaultClient{
		Id:          "emptyredirect3",
		Secret:      "secret3",
		RedirectUri: "",
	}
	storage.access["emptyredirect-token"] = &AccessData{
		Client:      emptyClient,
		AccessToken: "emptyredirect-token",
		ExpiresIn:   3600,
		CreatedAt:   time.Now(),
	}

	sconfig := NewServerConfig()
	server := NewServer(sconfig, storage)

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/info", nil)
	req.Header.Set("Authorization", "Bearer emptyredirect-token")

	ir := server.HandleInfoRequest(resp, req)
	if ir != nil {
		t.Fatal("Expected nil for access data with empty redirect URI client")
	}
	if !resp.IsError {
		t.Fatal("Expected error")
	}
	if resp.ErrorId != E_UNAUTHORIZED_CLIENT {
		t.Fatalf("Expected unauthorized_client, got %s", resp.ErrorId)
	}
	resp.Close()
}

// =============================================================================
// error.go: Get — unknown error id fallback (line 51)
// =============================================================================

// TestDefaultErrorsGetUnknown tests that requesting an unknown error id returns
// the id itself as the description.
func TestDefaultErrorsGetUnknown(t *testing.T) {
	errs := NewDefaultErrors()
	unknown := errs.Get("totally_unknown_error")
	if unknown != "totally_unknown_error" {
		t.Fatalf("Expected unknown error id to be returned as-is, got %s", unknown)
	}
}

// =============================================================================
// response.go: GetRedirectUrl — URL parse error (lines 116-118)
// =============================================================================

// TestGetRedirectUrlParseError tests that an invalid URL in a redirect response
// returns an error from GetRedirectUrl.
func TestGetRedirectUrlParseError(t *testing.T) {
	r := NewResponse(NewTestingStorage())
	r.SetRedirect("://invalid-url")

	_, err := r.GetRedirectUrl()
	if err == nil {
		t.Fatal("Expected error for invalid redirect URL")
	}
	r.Close()
}

// =============================================================================
// response_json.go: OutputJSON — redirect URL error (lines 20-22)
// =============================================================================

// TestOutputJSONRedirectUrlError tests that OutputJSON returns an error
// when the redirect URL is invalid.
func TestOutputJSONRedirectUrlError(t *testing.T) {
	r := NewResponse(NewTestingStorage())
	r.SetRedirect("://invalid-url")

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	err := OutputJSON(r, w, req)
	if err == nil {
		t.Fatal("Expected error from OutputJSON with invalid redirect URL")
	}
	r.Close()
}

// =============================================================================
// urivalidate.go: ParseUrls — base URL parse error (lines 26-28)
// =============================================================================

// TestParseUrlsBaseUrlError tests that an invalid base URL returns an error.
func TestParseUrlsBaseUrlError(t *testing.T) {
	_, _, err := ParseUrls("://invalid", "http://valid.com")
	if err == nil {
		t.Fatal("Expected error for invalid base URL")
	}
}

// =============================================================================
// urivalidate.go: ParseUrls — fragment in URL (lines 36-38)
// =============================================================================

// TestParseUrlsFragmentError tests that URLs with fragments are rejected.
func TestParseUrlsFragmentInBaseUrl(t *testing.T) {
	_, _, err := ParseUrls("http://example.com/path#fragment", "http://example.com/path")
	if err == nil {
		t.Fatal("Expected error for base URL with fragment")
	}
	if _, ok := err.(UriValidationError); !ok {
		t.Fatalf("Expected UriValidationError, got %T", err)
	}
}

func TestParseUrlsFragmentInRedirectUrl(t *testing.T) {
	_, _, err := ParseUrls("http://example.com/path", "http://example.com/path#fragment")
	if err == nil {
		t.Fatal("Expected error for redirect URL with fragment")
	}
	if _, ok := err.(UriValidationError); !ok {
		t.Fatalf("Expected UriValidationError, got %T", err)
	}
}

// =============================================================================
// urivalidate.go: ValidateUriList — non-validation error (lines 94-96)
// =============================================================================

// TestValidateUriListNonValidationError tests that a non-validation error
// (e.g., blank URL) propagates correctly.
func TestValidateUriListNonValidationError(t *testing.T) {
	// Empty redirect URI should cause ValidateUri to return a non-UriValidationError
	_, err := ValidateUriList("http://example.com", "", ";")
	if err == nil {
		t.Fatal("Expected error for blank redirect URI")
	}
}

// =============================================================================
// urivalidate.go: ValidateUri — blank URLs (lines 104-106)
// =============================================================================

// TestValidateUriBlankUrls tests that blank URLs return an error.
func TestValidateUriBlankBaseUrl(t *testing.T) {
	_, err := ValidateUri("", "http://example.com")
	if err == nil {
		t.Fatal("Expected error for blank base URL")
	}
}

func TestValidateUriBlankRedirectUrl(t *testing.T) {
	_, err := ValidateUri("http://example.com", "")
	if err == nil {
		t.Fatal("Expected error for blank redirect URL")
	}
}

// =============================================================================
// urivalidate.go: FirstUri — empty split result (line 138)
// =============================================================================

// TestFirstUriEmptyList tests FirstUri with an empty base URI list and separator.
func TestFirstUriEmptyListWithSeparator(t *testing.T) {
	result := FirstUri("", ";")
	if result != "" {
		t.Fatalf("Expected empty string, got %s", result)
	}
}

// =============================================================================
// util.go: CheckBasicAuth — base64 decode error (lines 48-50)
// and invalid message format (lines 52-54)
// =============================================================================

// TestCheckBasicAuthInvalidBase64 tests that an invalid base64 string returns an error.
func TestCheckBasicAuthInvalidBase64(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic not-valid-base64!!!")

	_, err := CheckBasicAuth(req)
	if err == nil {
		t.Fatal("Expected error for invalid base64")
	}
}

// TestCheckBasicAuthNoColon tests that a base64 string without a colon separator returns an error.
func TestCheckBasicAuthNoColon(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	// "nocolon" base64 encoded is "bm9jb2xvbg=="
	req.Header.Set("Authorization", "Basic bm9jb2xvbg==")

	_, err := CheckBasicAuth(req)
	if err == nil {
		t.Fatal("Expected error for missing colon in basic auth")
	}
	if err.Error() != "Invalid authorization message" {
		t.Fatalf("Unexpected error message: %s", err.Error())
	}
}

// =============================================================================
// Verify RetainTokenAfterRefresh config option
// =============================================================================

// TestFinishAccessRequestRetainTokenAfterRefresh verifies that when
// RetainTokenAfterRefresh is true, the old tokens are retained.
func TestFinishAccessRequestRetainTokenAfterRefresh(t *testing.T) {
	storage := NewTestingStorage()

	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE, REFRESH_TOKEN}
	sconfig.RetainTokenAfterRefresh = true
	server := NewServer(sconfig, storage)
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

	originalAccessToken := resp2.Output["access_token"].(string)
	refreshToken := resp2.Output["refresh_token"].(string)
	resp2.Close()

	// Step 3: Refresh the token
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
		t.Fatalf("Refresh failed: %v", resp3.InternalError)
	}

	// Verify old token is retained (not removed) when RetainTokenAfterRefresh is true
	_, err := storage.LoadAccess(originalAccessToken)
	if err != nil {
		t.Fatal("Expected original access token to be retained")
	}
	resp3.Close()
}

// =============================================================================
// authorize.go: HandleAuthorizeRequest — RequirePKCEForPublicClients (line 170-174)
// =============================================================================

// TestAuthorizeRequestRequirePKCEForPublicClient tests that public clients are
// required to provide a code_challenge when RequirePKCEForPublicClients is enabled.
func TestAuthorizeRequestRequirePKCEForPublicClient(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.AllowedAuthorizeTypes = AllowedAuthorizeType{CODE}
	sconfig.RequirePKCEForPublicClients = true
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	req, _ := http.NewRequest("GET", "http://localhost:14000/appauth", nil)
	req.Form = make(url.Values)
	req.Form.Set("response_type", string(CODE))
	req.Form.Set("client_id", "public-client")
	// No code_challenge provided

	ar := server.HandleAuthorizeRequest(resp, req)
	if ar != nil {
		t.Fatal("Expected nil for public client without PKCE challenge")
	}
	if !resp.IsError {
		t.Fatal("Expected error")
	}
	if resp.ErrorId != E_INVALID_REQUEST {
		t.Fatalf("Expected invalid_request, got %s", resp.ErrorId)
	}
	resp.Close()
}

// =============================================================================
// access.go: handleAuthorizationCodeRequest — PKCE plain verification success
// =============================================================================

// TestAccessAuthCodePKCEPlainSuccess tests a successful authorization code exchange
// with PKCE plain method.
func TestAccessAuthCodePKCEPlainSuccess(t *testing.T) {
	storage := NewTestingStorage()
	// Valid code_challenge for plain method (43-128 chars of [a-zA-Z0-9~._-])
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk0123456789"
	storage.authorize["pkce-plain"] = &AuthorizeData{
		Client:              storage.clients["1234"],
		Code:                "pkce-plain",
		ExpiresIn:           3600,
		CreatedAt:           time.Now(),
		RedirectUri:         "http://localhost:14000/appauth",
		CodeChallenge:       codeVerifier, // plain: challenge == verifier
		CodeChallengeMethod: PKCE_PLAIN,
	}

	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, storage)
	server.AccessTokenGen = &TestingAccessTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "pkce-plain")
	req.Form.Set("redirect_uri", "http://localhost:14000/appauth")
	req.Form.Set("code_verifier", codeVerifier)
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar == nil {
		t.Fatalf("Expected valid access request for PKCE plain, error=%v internal=%v", resp.ErrorId, resp.InternalError)
	}
	resp.Close()
}

// =============================================================================
// access.go: handleAuthorizationCodeRequest — PKCE verifier mismatch
// =============================================================================

// TestAccessAuthCodePKCEVerifierMismatch tests that a wrong PKCE verifier is rejected.
func TestAccessAuthCodePKCEVerifierMismatch(t *testing.T) {
	storage := NewTestingStorage()
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk0123456789"
	storage.authorize["pkce-mismatch"] = &AuthorizeData{
		Client:              storage.clients["1234"],
		Code:                "pkce-mismatch",
		ExpiresIn:           3600,
		CreatedAt:           time.Now(),
		RedirectUri:         "http://localhost:14000/appauth",
		CodeChallenge:       "wrong-challenge-value-that-does-not-match-the-verifier0000",
		CodeChallengeMethod: PKCE_PLAIN,
	}

	sconfig := NewServerConfig()
	sconfig.AllowedAccessTypes = AllowedAccessType{AUTHORIZATION_CODE}
	server := NewServer(sconfig, storage)
	server.AccessTokenGen = &TestingAccessTokenGen{}

	resp := server.NewResponse()
	req, _ := http.NewRequest("POST", "http://localhost:14000/appauth", nil)
	req.SetBasicAuth("1234", "aabbccdd")
	req.Form = make(url.Values)
	req.Form.Set("grant_type", string(AUTHORIZATION_CODE))
	req.Form.Set("code", "pkce-mismatch")
	req.Form.Set("redirect_uri", "http://localhost:14000/appauth")
	req.Form.Set("code_verifier", codeVerifier)
	req.PostForm = make(url.Values)

	ar := server.HandleAccessRequest(resp, req)
	if ar != nil {
		t.Fatal("Expected nil for PKCE verifier mismatch")
	}
	if !resp.IsError {
		t.Fatal("Expected error")
	}
	if resp.ErrorId != E_INVALID_GRANT {
		t.Fatalf("Expected invalid_grant, got %s", resp.ErrorId)
	}
	resp.Close()
}

// =============================================================================
// response.go: SetErrorUri — with non-200 ErrorStatusCode
// =============================================================================

// TestResponseSetErrorUriNon200StatusCode tests that SetErrorUri sets the status text
// when the ErrorStatusCode is not 200.
func TestResponseSetErrorUriNon200StatusCode(t *testing.T) {
	sconfig := NewServerConfig()
	sconfig.ErrorStatusCode = 400
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	resp.SetErrorUri("test_error", "test description", "http://error.example.com", "mystate")

	if !resp.IsError {
		t.Fatal("Expected error to be set")
	}
	if resp.StatusCode != 400 {
		t.Fatalf("Expected status code 400, got %d", resp.StatusCode)
	}
	if resp.StatusText != "test description" {
		t.Fatalf("Expected status text 'test description', got '%s'", resp.StatusText)
	}
	if resp.Output["error_uri"] != "http://error.example.com" {
		t.Fatal("Expected error_uri in output")
	}
	if resp.Output["state"] != "mystate" {
		t.Fatal("Expected state in output")
	}
	resp.Close()
}

// =============================================================================
// response_json.go: OutputJSON — existing Content-Type header preserved
// =============================================================================

// TestOutputJSONPreservesExistingContentType tests that OutputJSON does not override
// an existing Content-Type header.
func TestOutputJSONPreservesExistingContentType(t *testing.T) {
	sconfig := NewServerConfig()
	server := NewServer(sconfig, NewTestingStorage())

	resp := server.NewResponse()
	resp.Output["test"] = "value"

	w := httptest.NewRecorder()
	w.Header().Set("Content-Type", "text/plain")

	req, _ := http.NewRequest("GET", "/", nil)
	err := OutputJSON(resp, w, req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "text/plain" {
		t.Fatalf("Expected Content-Type to be preserved as 'text/plain', got '%s'", ct)
	}
	resp.Close()
}
