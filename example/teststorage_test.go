package example

import (
	"testing"
	"time"

	"github.com/openshift/osin"
)

func TestNewTestStorageCreatesConfidentialClient(t *testing.T) {
	storage := NewTestStorage()

	client, err := storage.GetClient("1234")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if client.GetId() != "1234" {
		t.Errorf("expected client ID '1234', got '%s'", client.GetId())
	}
	if client.GetSecret() != "aabbccdd" {
		t.Errorf("expected secret 'aabbccdd', got '%s'", client.GetSecret())
	}
	if client.GetRedirectUri() != "http://localhost:14000/appauth" {
		t.Errorf("expected redirect URI 'http://localhost:14000/appauth', got '%s'", client.GetRedirectUri())
	}
}

func TestNewTestStorageCreatesPublicClient(t *testing.T) {
	storage := NewTestStorage()

	client, err := storage.GetClient("public-app")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if client.GetId() != "public-app" {
		t.Errorf("expected client ID 'public-app', got '%s'", client.GetId())
	}
	if client.GetSecret() != "" {
		t.Errorf("expected empty secret for public client, got '%s'", client.GetSecret())
	}
	if client.GetRedirectUri() != "http://localhost:14000/appauth/public" {
		t.Errorf("expected redirect URI 'http://localhost:14000/appauth/public', got '%s'", client.GetRedirectUri())
	}
}

func TestNewTestStorageCreatesLimitedScopeClient(t *testing.T) {
	storage := NewTestStorage()

	client, err := storage.GetClient("limited-scope-app")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if client.GetId() != "limited-scope-app" {
		t.Errorf("expected client ID 'limited-scope-app', got '%s'", client.GetId())
	}
	if client.GetSecret() != "eeffgghh" {
		t.Errorf("expected secret 'eeffgghh', got '%s'", client.GetSecret())
	}
	if client.GetRedirectUri() != "http://localhost:14000/appauth/limited" {
		t.Errorf("expected redirect URI 'http://localhost:14000/appauth/limited', got '%s'", client.GetRedirectUri())
	}
}

func TestGetClientReturnsErrNotFoundForUnknownClient(t *testing.T) {
	storage := NewTestStorage()

	client, err := storage.GetClient("nonexistent")
	if err != osin.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
	if client != nil {
		t.Errorf("expected nil client, got %v", client)
	}
}

func TestSetClientAddsNewClient(t *testing.T) {
	storage := NewTestStorage()

	newClient := &osin.DefaultClient{
		Id:          "new-client",
		Secret:      "newsecret",
		RedirectUri: "http://localhost:14000/new",
	}

	err := storage.SetClient("new-client", newClient)
	if err != nil {
		t.Fatalf("expected no error from SetClient, got %v", err)
	}

	retrieved, err := storage.GetClient("new-client")
	if err != nil {
		t.Fatalf("expected no error from GetClient, got %v", err)
	}
	if retrieved.GetId() != "new-client" {
		t.Errorf("expected client ID 'new-client', got '%s'", retrieved.GetId())
	}
}

func TestSetClientOverwritesExistingClient(t *testing.T) {
	storage := NewTestStorage()

	updatedClient := &osin.DefaultClient{
		Id:          "1234",
		Secret:      "newpassword",
		RedirectUri: "http://localhost:14000/updated",
	}

	err := storage.SetClient("1234", updatedClient)
	if err != nil {
		t.Fatalf("expected no error from SetClient, got %v", err)
	}

	retrieved, err := storage.GetClient("1234")
	if err != nil {
		t.Fatalf("expected no error from GetClient, got %v", err)
	}
	if retrieved.GetSecret() != "newpassword" {
		t.Errorf("expected updated secret 'newpassword', got '%s'", retrieved.GetSecret())
	}
}

func TestCloneReturnsSameInstance(t *testing.T) {
	storage := NewTestStorage()

	cloned := storage.Clone()
	if cloned != storage {
		t.Error("expected Clone to return the same storage instance")
	}
}

func TestCloseDoesNotPanic(t *testing.T) {
	storage := NewTestStorage()
	// Close should be a no-op and not panic
	storage.Close()
}

func TestSaveAndLoadAuthorize(t *testing.T) {
	storage := NewTestStorage()
	client, _ := storage.GetClient("1234")

	data := &osin.AuthorizeData{
		Client:      client,
		Code:        "testcode",
		ExpiresIn:   3600,
		CreatedAt:   time.Now(),
		RedirectUri: "http://localhost:14000/appauth",
	}

	err := storage.SaveAuthorize(data)
	if err != nil {
		t.Fatalf("expected no error from SaveAuthorize, got %v", err)
	}

	loaded, err := storage.LoadAuthorize("testcode")
	if err != nil {
		t.Fatalf("expected no error from LoadAuthorize, got %v", err)
	}
	if loaded.Code != "testcode" {
		t.Errorf("expected code 'testcode', got '%s'", loaded.Code)
	}
	if loaded.Client.GetId() != "1234" {
		t.Errorf("expected client ID '1234', got '%s'", loaded.Client.GetId())
	}
}

func TestLoadAuthorizeReturnsErrNotFound(t *testing.T) {
	storage := NewTestStorage()

	_, err := storage.LoadAuthorize("nonexistent")
	if err != osin.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestRemoveAuthorize(t *testing.T) {
	storage := NewTestStorage()
	client, _ := storage.GetClient("1234")

	data := &osin.AuthorizeData{
		Client:    client,
		Code:      "removeme",
		ExpiresIn: 3600,
		CreatedAt: time.Now(),
	}
	storage.SaveAuthorize(data)

	err := storage.RemoveAuthorize("removeme")
	if err != nil {
		t.Fatalf("expected no error from RemoveAuthorize, got %v", err)
	}

	_, err = storage.LoadAuthorize("removeme")
	if err != osin.ErrNotFound {
		t.Errorf("expected ErrNotFound after removal, got %v", err)
	}
}

func TestRemoveAuthorizeNonexistentIsNoOp(t *testing.T) {
	storage := NewTestStorage()

	err := storage.RemoveAuthorize("doesnotexist")
	if err != nil {
		t.Errorf("expected no error when removing nonexistent authorize, got %v", err)
	}
}

func TestSaveAndLoadAccess(t *testing.T) {
	storage := NewTestStorage()
	client, _ := storage.GetClient("1234")

	data := &osin.AccessData{
		Client:      client,
		AccessToken: "access123",
		ExpiresIn:   3600,
		CreatedAt:   time.Now(),
	}

	err := storage.SaveAccess(data)
	if err != nil {
		t.Fatalf("expected no error from SaveAccess, got %v", err)
	}

	loaded, err := storage.LoadAccess("access123")
	if err != nil {
		t.Fatalf("expected no error from LoadAccess, got %v", err)
	}
	if loaded.AccessToken != "access123" {
		t.Errorf("expected access token 'access123', got '%s'", loaded.AccessToken)
	}
}

func TestSaveAccessWithRefreshToken(t *testing.T) {
	storage := NewTestStorage()
	client, _ := storage.GetClient("1234")

	data := &osin.AccessData{
		Client:       client,
		AccessToken:  "access456",
		RefreshToken: "refresh456",
		ExpiresIn:    3600,
		CreatedAt:    time.Now(),
	}

	err := storage.SaveAccess(data)
	if err != nil {
		t.Fatalf("expected no error from SaveAccess, got %v", err)
	}

	loaded, err := storage.LoadRefresh("refresh456")
	if err != nil {
		t.Fatalf("expected no error from LoadRefresh, got %v", err)
	}
	if loaded.AccessToken != "access456" {
		t.Errorf("expected access token 'access456', got '%s'", loaded.AccessToken)
	}
}

func TestSaveAccessWithoutRefreshTokenDoesNotCreateRefreshEntry(t *testing.T) {
	storage := NewTestStorage()
	client, _ := storage.GetClient("1234")

	data := &osin.AccessData{
		Client:      client,
		AccessToken: "access789",
		ExpiresIn:   3600,
		CreatedAt:   time.Now(),
	}

	storage.SaveAccess(data)

	_, err := storage.LoadRefresh("access789")
	if err != osin.ErrNotFound {
		t.Errorf("expected ErrNotFound for nonexistent refresh token, got %v", err)
	}
}

func TestLoadAccessReturnsErrNotFound(t *testing.T) {
	storage := NewTestStorage()

	_, err := storage.LoadAccess("nonexistent")
	if err != osin.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestRemoveAccess(t *testing.T) {
	storage := NewTestStorage()
	client, _ := storage.GetClient("1234")

	data := &osin.AccessData{
		Client:      client,
		AccessToken: "removeme",
		ExpiresIn:   3600,
		CreatedAt:   time.Now(),
	}
	storage.SaveAccess(data)

	err := storage.RemoveAccess("removeme")
	if err != nil {
		t.Fatalf("expected no error from RemoveAccess, got %v", err)
	}

	_, err = storage.LoadAccess("removeme")
	if err != osin.ErrNotFound {
		t.Errorf("expected ErrNotFound after removal, got %v", err)
	}
}

func TestRemoveAccessNonexistentIsNoOp(t *testing.T) {
	storage := NewTestStorage()

	err := storage.RemoveAccess("doesnotexist")
	if err != nil {
		t.Errorf("expected no error when removing nonexistent access, got %v", err)
	}
}

func TestLoadRefreshReturnsErrNotFound(t *testing.T) {
	storage := NewTestStorage()

	_, err := storage.LoadRefresh("nonexistent")
	if err != osin.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestRemoveRefresh(t *testing.T) {
	storage := NewTestStorage()
	client, _ := storage.GetClient("1234")

	data := &osin.AccessData{
		Client:       client,
		AccessToken:  "accessforrefresh",
		RefreshToken: "refreshremoveme",
		ExpiresIn:    3600,
		CreatedAt:    time.Now(),
	}
	storage.SaveAccess(data)

	err := storage.RemoveRefresh("refreshremoveme")
	if err != nil {
		t.Fatalf("expected no error from RemoveRefresh, got %v", err)
	}

	_, err = storage.LoadRefresh("refreshremoveme")
	if err != osin.ErrNotFound {
		t.Errorf("expected ErrNotFound after removal, got %v", err)
	}

	// The access token should still be loadable
	loaded, err := storage.LoadAccess("accessforrefresh")
	if err != nil {
		t.Fatalf("expected access token to still exist, got %v", err)
	}
	if loaded.AccessToken != "accessforrefresh" {
		t.Errorf("expected access token 'accessforrefresh', got '%s'", loaded.AccessToken)
	}
}

func TestRemoveRefreshNonexistentIsNoOp(t *testing.T) {
	storage := NewTestStorage()

	err := storage.RemoveRefresh("doesnotexist")
	if err != nil {
		t.Errorf("expected no error when removing nonexistent refresh, got %v", err)
	}
}

func TestPublicClientHasEmptySecret(t *testing.T) {
	storage := NewTestStorage()

	client, err := storage.GetClient("public-app")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	defaultClient, ok := client.(*osin.DefaultClient)
	if !ok {
		t.Fatal("expected client to be *osin.DefaultClient")
	}

	// Public clients should match empty secret
	if !defaultClient.ClientSecretMatches("") {
		t.Error("expected public client to match empty secret")
	}
	// Public clients should NOT match non-empty secrets
	if defaultClient.ClientSecretMatches("somesecret") {
		t.Error("expected public client to reject non-empty secret")
	}
}

func TestConfidentialClientSecretMatching(t *testing.T) {
	storage := NewTestStorage()

	client, err := storage.GetClient("1234")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	defaultClient, ok := client.(*osin.DefaultClient)
	if !ok {
		t.Fatal("expected client to be *osin.DefaultClient")
	}

	if !defaultClient.ClientSecretMatches("aabbccdd") {
		t.Error("expected confidential client to match correct secret")
	}
	if defaultClient.ClientSecretMatches("wrongsecret") {
		t.Error("expected confidential client to reject wrong secret")
	}
	if defaultClient.ClientSecretMatches("") {
		t.Error("expected confidential client to reject empty secret")
	}
}

func TestLimitedScopeClientSecretMatching(t *testing.T) {
	storage := NewTestStorage()

	client, err := storage.GetClient("limited-scope-app")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	defaultClient, ok := client.(*osin.DefaultClient)
	if !ok {
		t.Fatal("expected client to be *osin.DefaultClient")
	}

	if !defaultClient.ClientSecretMatches("eeffgghh") {
		t.Error("expected limited-scope client to match correct secret")
	}
	if defaultClient.ClientSecretMatches("aabbccdd") {
		t.Error("expected limited-scope client to reject confidential client's secret")
	}
}

func TestAllThreeClientsHaveDistinctRedirectURIs(t *testing.T) {
	storage := NewTestStorage()

	confidential, _ := storage.GetClient("1234")
	public, _ := storage.GetClient("public-app")
	limited, _ := storage.GetClient("limited-scope-app")

	uris := map[string]string{
		"confidential": confidential.GetRedirectUri(),
		"public":       public.GetRedirectUri(),
		"limited":      limited.GetRedirectUri(),
	}

	seen := make(map[string]string)
	for name, uri := range uris {
		if prev, exists := seen[uri]; exists {
			t.Errorf("clients '%s' and '%s' share the same redirect URI: %s", prev, name, uri)
		}
		seen[uri] = name
	}
}

func TestAllThreeClientsHaveDistinctIDs(t *testing.T) {
	storage := NewTestStorage()

	ids := []string{"1234", "public-app", "limited-scope-app"}
	for _, id := range ids {
		client, err := storage.GetClient(id)
		if err != nil {
			t.Errorf("expected client '%s' to exist, got error: %v", id, err)
			continue
		}
		if client.GetId() != id {
			t.Errorf("expected client ID '%s', got '%s'", id, client.GetId())
		}
	}
}

func TestStorageCRUDLifecycle(t *testing.T) {
	storage := NewTestStorage()
	client, _ := storage.GetClient("public-app")

	// Save authorize data
	authData := &osin.AuthorizeData{
		Client:      client,
		Code:        "lifecycle-auth",
		ExpiresIn:   3600,
		CreatedAt:   time.Now(),
		RedirectUri: "http://localhost:14000/appauth/public",
	}
	if err := storage.SaveAuthorize(authData); err != nil {
		t.Fatalf("SaveAuthorize failed: %v", err)
	}

	// Save access data with refresh token
	accessData := &osin.AccessData{
		Client:        client,
		AuthorizeData: authData,
		AccessToken:   "lifecycle-access",
		RefreshToken:  "lifecycle-refresh",
		ExpiresIn:     3600,
		CreatedAt:     time.Now(),
	}
	if err := storage.SaveAccess(accessData); err != nil {
		t.Fatalf("SaveAccess failed: %v", err)
	}

	// Verify all data is retrievable
	if _, err := storage.LoadAuthorize("lifecycle-auth"); err != nil {
		t.Errorf("LoadAuthorize failed: %v", err)
	}
	if _, err := storage.LoadAccess("lifecycle-access"); err != nil {
		t.Errorf("LoadAccess failed: %v", err)
	}
	if _, err := storage.LoadRefresh("lifecycle-refresh"); err != nil {
		t.Errorf("LoadRefresh failed: %v", err)
	}

	// Remove in order: refresh, access, authorize
	if err := storage.RemoveRefresh("lifecycle-refresh"); err != nil {
		t.Errorf("RemoveRefresh failed: %v", err)
	}
	if _, err := storage.LoadRefresh("lifecycle-refresh"); err != osin.ErrNotFound {
		t.Errorf("expected ErrNotFound after RemoveRefresh, got %v", err)
	}

	if err := storage.RemoveAccess("lifecycle-access"); err != nil {
		t.Errorf("RemoveAccess failed: %v", err)
	}
	if _, err := storage.LoadAccess("lifecycle-access"); err != osin.ErrNotFound {
		t.Errorf("expected ErrNotFound after RemoveAccess, got %v", err)
	}

	if err := storage.RemoveAuthorize("lifecycle-auth"); err != nil {
		t.Errorf("RemoveAuthorize failed: %v", err)
	}
	if _, err := storage.LoadAuthorize("lifecycle-auth"); err != osin.ErrNotFound {
		t.Errorf("expected ErrNotFound after RemoveAuthorize, got %v", err)
	}
}
