package example

import (
	"testing"

	"github.com/openshift/osin"
)

func TestNewTestStorageReturnsAllClients(t *testing.T) {
	storage := NewTestStorage()

	expectedClientIDs := []string{"1234", "public-app", "limited-scope-app"}
	for _, id := range expectedClientIDs {
		client, err := storage.GetClient(id)
		if err != nil {
			t.Fatalf("Expected client %q to exist, got error: %v", id, err)
		}
		if client.GetId() != id {
			t.Errorf("Expected client ID %q, got %q", id, client.GetId())
		}
	}
}

func TestConfidentialClientProperties(t *testing.T) {
	storage := NewTestStorage()

	client, err := storage.GetClient("1234")
	if err != nil {
		t.Fatalf("Failed to get confidential client: %v", err)
	}

	if client.GetId() != "1234" {
		t.Errorf("Expected ID %q, got %q", "1234", client.GetId())
	}
	if client.GetSecret() != "aabbccdd" {
		t.Errorf("Expected secret %q, got %q", "aabbccdd", client.GetSecret())
	}
	if client.GetRedirectUri() != "http://localhost:14000/appauth" {
		t.Errorf("Expected redirect URI %q, got %q",
			"http://localhost:14000/appauth", client.GetRedirectUri())
	}
}

func TestPublicClientProperties(t *testing.T) {
	storage := NewTestStorage()

	client, err := storage.GetClient("public-app")
	if err != nil {
		t.Fatalf("Failed to get public client: %v", err)
	}

	if client.GetId() != "public-app" {
		t.Errorf("Expected ID %q, got %q", "public-app", client.GetId())
	}
	if client.GetSecret() != "" {
		t.Errorf("Public client should have empty secret, got %q", client.GetSecret())
	}
	if client.GetRedirectUri() != "http://localhost:14000/appauth" {
		t.Errorf("Expected redirect URI %q, got %q",
			"http://localhost:14000/appauth", client.GetRedirectUri())
	}
}

func TestLimitedScopeClientProperties(t *testing.T) {
	storage := NewTestStorage()

	client, err := storage.GetClient("limited-scope-app")
	if err != nil {
		t.Fatalf("Failed to get limited-scope client: %v", err)
	}

	if client.GetId() != "limited-scope-app" {
		t.Errorf("Expected ID %q, got %q", "limited-scope-app", client.GetId())
	}
	if client.GetSecret() != "eeffgghh" {
		t.Errorf("Expected secret %q, got %q", "eeffgghh", client.GetSecret())
	}
	if client.GetRedirectUri() != "http://localhost:14000/appauth/limited" {
		t.Errorf("Expected redirect URI %q, got %q",
			"http://localhost:14000/appauth/limited", client.GetRedirectUri())
	}
}

func TestGetClientReturnsErrorForUnknownClient(t *testing.T) {
	storage := NewTestStorage()

	_, err := storage.GetClient("nonexistent-client")
	if err == nil {
		t.Fatal("Expected error for nonexistent client, got nil")
	}
	if err != osin.ErrNotFound {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

func TestSetClientOverridesExistingClient(t *testing.T) {
	storage := NewTestStorage()

	newClient := &osin.DefaultClient{
		Id:          "1234",
		Secret:      "newsecret",
		RedirectUri: "http://localhost:14000/new",
	}

	err := storage.SetClient("1234", newClient)
	if err != nil {
		t.Fatalf("SetClient failed: %v", err)
	}

	client, err := storage.GetClient("1234")
	if err != nil {
		t.Fatalf("GetClient failed after SetClient: %v", err)
	}
	if client.GetSecret() != "newsecret" {
		t.Errorf("Expected updated secret %q, got %q", "newsecret", client.GetSecret())
	}
}

func TestSetClientAddsNewClient(t *testing.T) {
	storage := NewTestStorage()

	newClient := &osin.DefaultClient{
		Id:          "brand-new-client",
		Secret:      "secret123",
		RedirectUri: "http://localhost:14000/new",
	}

	err := storage.SetClient("brand-new-client", newClient)
	if err != nil {
		t.Fatalf("SetClient failed: %v", err)
	}

	client, err := storage.GetClient("brand-new-client")
	if err != nil {
		t.Fatalf("GetClient failed for newly added client: %v", err)
	}
	if client.GetId() != "brand-new-client" {
		t.Errorf("Expected ID %q, got %q", "brand-new-client", client.GetId())
	}
}

func TestStorageCloneReturnsSameInstance(t *testing.T) {
	storage := NewTestStorage()
	cloned := storage.Clone()

	if cloned != storage {
		t.Error("Clone should return the same storage instance")
	}
}

func TestAuthorizeDataLifecycle(t *testing.T) {
	storage := NewTestStorage()

	client, _ := storage.GetClient("1234")
	authData := &osin.AuthorizeData{
		Client:      client,
		Code:        "test-auth-code",
		ExpiresIn:   3600,
		RedirectUri: "http://localhost:14000/appauth",
	}

	// Save
	if err := storage.SaveAuthorize(authData); err != nil {
		t.Fatalf("SaveAuthorize failed: %v", err)
	}

	// Load
	loaded, err := storage.LoadAuthorize("test-auth-code")
	if err != nil {
		t.Fatalf("LoadAuthorize failed: %v", err)
	}
	if loaded.Code != "test-auth-code" {
		t.Errorf("Expected code %q, got %q", "test-auth-code", loaded.Code)
	}
	if loaded.Client.GetId() != "1234" {
		t.Errorf("Expected client ID %q, got %q", "1234", loaded.Client.GetId())
	}

	// Remove
	if err := storage.RemoveAuthorize("test-auth-code"); err != nil {
		t.Fatalf("RemoveAuthorize failed: %v", err)
	}

	// Verify removed
	_, err = storage.LoadAuthorize("test-auth-code")
	if err != osin.ErrNotFound {
		t.Errorf("Expected ErrNotFound after removal, got %v", err)
	}
}

func TestAccessDataLifecycle(t *testing.T) {
	storage := NewTestStorage()

	client, _ := storage.GetClient("limited-scope-app")
	accessData := &osin.AccessData{
		Client:       client,
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		ExpiresIn:    3600,
	}

	// Save
	if err := storage.SaveAccess(accessData); err != nil {
		t.Fatalf("SaveAccess failed: %v", err)
	}

	// Load access token
	loaded, err := storage.LoadAccess("test-access-token")
	if err != nil {
		t.Fatalf("LoadAccess failed: %v", err)
	}
	if loaded.AccessToken != "test-access-token" {
		t.Errorf("Expected access token %q, got %q",
			"test-access-token", loaded.AccessToken)
	}
	if loaded.Client.GetId() != "limited-scope-app" {
		t.Errorf("Expected client ID %q, got %q",
			"limited-scope-app", loaded.Client.GetId())
	}

	// Load via refresh token
	refreshLoaded, err := storage.LoadRefresh("test-refresh-token")
	if err != nil {
		t.Fatalf("LoadRefresh failed: %v", err)
	}
	if refreshLoaded.AccessToken != "test-access-token" {
		t.Errorf("Expected access token %q via refresh, got %q",
			"test-access-token", refreshLoaded.AccessToken)
	}

	// Remove refresh token
	if err := storage.RemoveRefresh("test-refresh-token"); err != nil {
		t.Fatalf("RemoveRefresh failed: %v", err)
	}
	_, err = storage.LoadRefresh("test-refresh-token")
	if err != osin.ErrNotFound {
		t.Errorf("Expected ErrNotFound after refresh removal, got %v", err)
	}

	// Remove access token
	if err := storage.RemoveAccess("test-access-token"); err != nil {
		t.Fatalf("RemoveAccess failed: %v", err)
	}
	_, err = storage.LoadAccess("test-access-token")
	if err != osin.ErrNotFound {
		t.Errorf("Expected ErrNotFound after access removal, got %v", err)
	}
}

func TestAccessDataWithoutRefreshToken(t *testing.T) {
	storage := NewTestStorage()

	client, _ := storage.GetClient("public-app")
	accessData := &osin.AccessData{
		Client:      client,
		AccessToken: "public-access-token",
		ExpiresIn:   3600,
	}

	if err := storage.SaveAccess(accessData); err != nil {
		t.Fatalf("SaveAccess failed: %v", err)
	}

	loaded, err := storage.LoadAccess("public-access-token")
	if err != nil {
		t.Fatalf("LoadAccess failed: %v", err)
	}
	if loaded.RefreshToken != "" {
		t.Errorf("Expected empty refresh token, got %q", loaded.RefreshToken)
	}
}

func TestLoadRefreshReturnsErrorForUnknownToken(t *testing.T) {
	storage := NewTestStorage()

	_, err := storage.LoadRefresh("nonexistent-refresh-token")
	if err != osin.ErrNotFound {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

func TestLoadAccessReturnsErrorForUnknownToken(t *testing.T) {
	storage := NewTestStorage()

	_, err := storage.LoadAccess("nonexistent-access-token")
	if err != osin.ErrNotFound {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

func TestLoadAuthorizeReturnsErrorForUnknownCode(t *testing.T) {
	storage := NewTestStorage()

	_, err := storage.LoadAuthorize("nonexistent-code")
	if err != osin.ErrNotFound {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}
}

func TestMultipleClientsAreIndependent(t *testing.T) {
	storage := NewTestStorage()

	confidential, _ := storage.GetClient("1234")
	public, _ := storage.GetClient("public-app")
	limited, _ := storage.GetClient("limited-scope-app")

	// Verify each client has distinct properties
	if confidential.GetRedirectUri() == limited.GetRedirectUri() {
		t.Error("Confidential and limited-scope clients should have different redirect URIs")
	}
	if public.GetSecret() == confidential.GetSecret() {
		t.Error("Public and confidential clients should have different secrets")
	}
	if public.GetSecret() != "" {
		t.Error("Public client should have empty secret")
	}
	if limited.GetSecret() == confidential.GetSecret() {
		t.Error("Limited-scope and confidential clients should have different secrets")
	}
}

func TestAuthorizeDataWithDifferentClientTypes(t *testing.T) {
	testCases := []struct {
		name     string
		clientID string
	}{
		{"confidential client", "1234"},
		{"public client", "public-app"},
		{"limited-scope client", "limited-scope-app"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			storage := NewTestStorage()
			client, err := storage.GetClient(tc.clientID)
			if err != nil {
				t.Fatalf("Failed to get client %q: %v", tc.clientID, err)
			}

			authData := &osin.AuthorizeData{
				Client:      client,
				Code:        "code-" + tc.clientID,
				ExpiresIn:   3600,
				RedirectUri: client.GetRedirectUri(),
			}

			if err := storage.SaveAuthorize(authData); err != nil {
				t.Fatalf("SaveAuthorize failed: %v", err)
			}

			loaded, err := storage.LoadAuthorize("code-" + tc.clientID)
			if err != nil {
				t.Fatalf("LoadAuthorize failed: %v", err)
			}

			if loaded.Client.GetId() != tc.clientID {
				t.Errorf("Expected client ID %q, got %q",
					tc.clientID, loaded.Client.GetId())
			}
		})
	}
}

func TestAccessDataWithDifferentClientTypes(t *testing.T) {
	testCases := []struct {
		name     string
		clientID string
	}{
		{"confidential client", "1234"},
		{"public client", "public-app"},
		{"limited-scope client", "limited-scope-app"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			storage := NewTestStorage()
			client, err := storage.GetClient(tc.clientID)
			if err != nil {
				t.Fatalf("Failed to get client %q: %v", tc.clientID, err)
			}

			accessData := &osin.AccessData{
				Client:       client,
				AccessToken:  "token-" + tc.clientID,
				RefreshToken: "refresh-" + tc.clientID,
				ExpiresIn:    3600,
			}

			if err := storage.SaveAccess(accessData); err != nil {
				t.Fatalf("SaveAccess failed: %v", err)
			}

			loaded, err := storage.LoadAccess("token-" + tc.clientID)
			if err != nil {
				t.Fatalf("LoadAccess failed: %v", err)
			}

			if loaded.Client.GetId() != tc.clientID {
				t.Errorf("Expected client ID %q, got %q",
					tc.clientID, loaded.Client.GetId())
			}

			refreshLoaded, err := storage.LoadRefresh("refresh-" + tc.clientID)
			if err != nil {
				t.Fatalf("LoadRefresh failed: %v", err)
			}
			if refreshLoaded.Client.GetId() != tc.clientID {
				t.Errorf("Expected client ID %q via refresh, got %q",
					tc.clientID, refreshLoaded.Client.GetId())
			}
		})
	}
}
