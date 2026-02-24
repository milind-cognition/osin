package example

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/openshift/osin"
)

// testClient implements osin.Client for use in tests.
type testClient struct {
	id          string
	secret      string
	redirectURI string
}

func (c *testClient) GetId() string            { return c.id }
func (c *testClient) GetSecret() string        { return c.secret }
func (c *testClient) GetRedirectUri() string   { return c.redirectURI }
func (c *testClient) GetUserData() interface{} { return nil }

func newTestAuthorizeRequest(scope string) *osin.AuthorizeRequest {
	return &osin.AuthorizeRequest{
		Client: &testClient{
			id:          "test-client",
			secret:      "secret",
			redirectURI: "http://localhost/callback",
		},
		Scope: scope,
	}
}

// ---------------------------------------------------------------------------
// HandleLoginPage tests
// ---------------------------------------------------------------------------

func TestHandleLoginPage_ValidCredentials(t *testing.T) {
	ar := newTestAuthorizeRequest("read")
	w := httptest.NewRecorder()

	form := url.Values{}
	form.Set("login", "test")
	form.Set("password", "test")

	r := httptest.NewRequest("POST", "/authorize?response_type=code", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	result := HandleLoginPage(ar, w, r)
	if !result {
		t.Fatal("expected HandleLoginPage to return true for valid credentials")
	}
}

func TestHandleLoginPage_InvalidCredentials(t *testing.T) {
	ar := newTestAuthorizeRequest("read")
	w := httptest.NewRecorder()

	form := url.Values{}
	form.Set("login", "wrong")
	form.Set("password", "wrong")

	r := httptest.NewRequest("POST", "/authorize?response_type=code", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	result := HandleLoginPage(ar, w, r)
	if result {
		t.Fatal("expected HandleLoginPage to return false for invalid credentials")
	}

	body := w.Body.String()
	if !strings.Contains(body, "LOGIN test-client") {
		t.Error("login page should display the client ID")
	}
}

func TestHandleLoginPage_GETRendersForm(t *testing.T) {
	ar := newTestAuthorizeRequest("read")
	w := httptest.NewRecorder()

	r := httptest.NewRequest("GET", "/authorize?response_type=code&state=xyz", nil)

	result := HandleLoginPage(ar, w, r)
	if result {
		t.Fatal("expected HandleLoginPage to return false for GET request")
	}

	body := w.Body.String()
	if !strings.Contains(body, "<form") {
		t.Error("login page should contain a form element")
	}
	if !strings.Contains(body, `name="login"`) {
		t.Error("login page should contain a login input")
	}
	if !strings.Contains(body, `name="password"`) {
		t.Error("login page should contain a password input")
	}
}

// ---------------------------------------------------------------------------
// HandleConsentPage tests
// ---------------------------------------------------------------------------

func TestHandleConsentPage_ApproveAllScopes(t *testing.T) {
	ar := newTestAuthorizeRequest("read write admin")

	form := url.Values{}
	form.Set("consent_submitted", "1")
	form.Add("approved_scope", "read")
	form.Add("approved_scope", "write")
	form.Add("approved_scope", "admin")

	r := httptest.NewRequest("POST", "/authorize?scope=read+write+admin", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	consented, scopes := HandleConsentPage(ar, w, r)

	if !consented {
		t.Fatal("expected consented to be true")
	}
	if scopes != "read write admin" {
		t.Errorf("expected scopes 'read write admin', got '%s'", scopes)
	}
}

func TestHandleConsentPage_ApproveSubsetOfScopes(t *testing.T) {
	ar := newTestAuthorizeRequest("read write admin")

	form := url.Values{}
	form.Set("consent_submitted", "1")
	form.Add("approved_scope", "read")

	r := httptest.NewRequest("POST", "/authorize?scope=read+write+admin", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	consented, scopes := HandleConsentPage(ar, w, r)

	if !consented {
		t.Fatal("expected consented to be true")
	}
	if scopes != "read" {
		t.Errorf("expected scopes 'read', got '%s'", scopes)
	}
}

func TestHandleConsentPage_DenyAll(t *testing.T) {
	ar := newTestAuthorizeRequest("read write admin")

	form := url.Values{}
	form.Set("consent_submitted", "1")
	form.Set("deny_all", "1")

	r := httptest.NewRequest("POST", "/authorize?scope=read+write+admin", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	consented, scopes := HandleConsentPage(ar, w, r)

	if !consented {
		t.Fatal("expected consented to be true when deny_all is set")
	}
	if scopes != "" {
		t.Errorf("expected empty scopes on deny, got '%s'", scopes)
	}
}

func TestHandleConsentPage_NoScopesChecked(t *testing.T) {
	ar := newTestAuthorizeRequest("read write admin")

	form := url.Values{}
	form.Set("consent_submitted", "1")
	// no approved_scope values

	r := httptest.NewRequest("POST", "/authorize?scope=read+write+admin", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	consented, scopes := HandleConsentPage(ar, w, r)

	if !consented {
		t.Fatal("expected consented to be true")
	}
	if scopes != "" {
		t.Errorf("expected empty scopes when none checked, got '%s'", scopes)
	}
}

func TestHandleConsentPage_GETRendersConsentForm(t *testing.T) {
	ar := newTestAuthorizeRequest("read write admin")

	r := httptest.NewRequest("GET", "/authorize?scope=read+write+admin&client_id=test-client", nil)
	w := httptest.NewRecorder()

	consented, scopes := HandleConsentPage(ar, w, r)

	if consented {
		t.Fatal("expected consented to be false for GET request")
	}
	if scopes != "" {
		t.Errorf("expected empty scopes for GET request, got '%s'", scopes)
	}

	body := w.Body.String()

	// Verify key elements of the consent page HTML
	if !strings.Contains(body, "Authorization Request") {
		t.Error("consent page should contain 'Authorization Request' heading")
	}
	if !strings.Contains(body, "test-client") {
		t.Error("consent page should display the client ID")
	}
	if !strings.Contains(body, `name="approved_scope"`) {
		t.Error("consent page should contain scope checkboxes")
	}
	if !strings.Contains(body, `value="read"`) {
		t.Error("consent page should contain 'read' scope checkbox")
	}
	if !strings.Contains(body, `value="write"`) {
		t.Error("consent page should contain 'write' scope checkbox")
	}
	if !strings.Contains(body, `value="admin"`) {
		t.Error("consent page should contain 'admin' scope checkbox")
	}
	if !strings.Contains(body, `name="consent_submitted"`) {
		t.Error("consent page should contain hidden consent_submitted field")
	}
	if !strings.Contains(body, `name="deny_all"`) {
		t.Error("consent page should contain deny_all button")
	}
}

func TestHandleConsentPage_ForwardsLoginCredentials(t *testing.T) {
	ar := newTestAuthorizeRequest("read")

	form := url.Values{}
	form.Set("login", "test")
	form.Set("password", "test")

	// Simulate a GET with login/password in query (from first POST to login form)
	r := httptest.NewRequest("GET", "/authorize?scope=read&login=test&password=test", nil)
	w := httptest.NewRecorder()

	consented, _ := HandleConsentPage(ar, w, r)
	if consented {
		t.Fatal("expected consented to be false for GET request")
	}

	body := w.Body.String()
	if !strings.Contains(body, `name="login"`) {
		t.Error("consent page should contain hidden login field")
	}
	if !strings.Contains(body, `value="test"`) {
		t.Error("consent page should forward login credential values")
	}
	if !strings.Contains(body, `name="password"`) {
		t.Error("consent page should contain hidden password field")
	}
}

func TestHandleConsentPage_SingleScope(t *testing.T) {
	ar := newTestAuthorizeRequest("read")

	form := url.Values{}
	form.Set("consent_submitted", "1")
	form.Add("approved_scope", "read")

	r := httptest.NewRequest("POST", "/authorize?scope=read", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	consented, scopes := HandleConsentPage(ar, w, r)

	if !consented {
		t.Fatal("expected consented to be true")
	}
	if scopes != "read" {
		t.Errorf("expected scopes 'read', got '%s'", scopes)
	}
}

func TestHandleConsentPage_GETDoesNotConsentOnMissingConsentSubmitted(t *testing.T) {
	ar := newTestAuthorizeRequest("read write")

	// POST without consent_submitted should render the form, not process consent
	form := url.Values{}
	form.Set("login", "test")
	form.Set("password", "test")

	r := httptest.NewRequest("POST", "/authorize?scope=read+write", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	consented, scopes := HandleConsentPage(ar, w, r)

	if consented {
		t.Fatal("expected consented to be false when consent_submitted is not set")
	}
	if scopes != "" {
		t.Errorf("expected empty scopes, got '%s'", scopes)
	}
}

func TestHandleConsentPage_ScopeNotReadFromURLQuery(t *testing.T) {
	ar := newTestAuthorizeRequest("read write admin")

	// Put "scope" in the URL query and "approved_scope" in POST body.
	// Only approved_scope from POST body should be returned.
	form := url.Values{}
	form.Set("consent_submitted", "1")
	form.Add("approved_scope", "write")

	r := httptest.NewRequest("POST", "/authorize?scope=read+write+admin", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	consented, scopes := HandleConsentPage(ar, w, r)

	if !consented {
		t.Fatal("expected consented to be true")
	}
	if scopes != "write" {
		t.Errorf("expected only POST body scopes 'write', got '%s'", scopes)
	}
}

func TestHandleConsentPage_EmptyScopeRendersForm(t *testing.T) {
	// When ar.Scope is empty string, the fallback produces []string{""}
	ar := newTestAuthorizeRequest("")

	r := httptest.NewRequest("GET", "/authorize", nil)
	w := httptest.NewRecorder()

	consented, scopes := HandleConsentPage(ar, w, r)

	if consented {
		t.Fatal("expected consented to be false for GET request")
	}
	if scopes != "" {
		t.Errorf("expected empty scopes, got '%s'", scopes)
	}

	body := w.Body.String()
	if !strings.Contains(body, "<form") {
		t.Error("consent page should render a form even with empty scope")
	}
}
