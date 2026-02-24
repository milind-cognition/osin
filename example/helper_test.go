package example

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/openshift/osin"
)

// newTestAuthorizeRequest creates an AuthorizeRequest with sensible defaults
// for use in tests.
func newTestAuthorizeRequest(scope string) *osin.AuthorizeRequest {
	return &osin.AuthorizeRequest{
		Client: &osin.DefaultClient{
			Id:          "test-client",
			Secret:      "secret",
			RedirectUri: "http://localhost:14000/appauth",
		},
		Scope: scope,
	}
}

// --- HandleLoginPage tests ---

func TestHandleLoginPage_SuccessfulLogin(t *testing.T) {
	ar := newTestAuthorizeRequest("read write")

	form := url.Values{}
	form.Set("login", "test")
	form.Set("password", "test")

	req, err := http.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	result := HandleLoginPage(ar, w, req)

	if !result {
		t.Error("HandleLoginPage should return true for valid credentials")
	}

	// On success, no HTML should be written to the response body
	if w.Body.Len() != 0 {
		t.Errorf("Expected empty body on successful login, got %q", w.Body.String())
	}
}

func TestHandleLoginPage_InvalidPassword(t *testing.T) {
	ar := newTestAuthorizeRequest("read")

	form := url.Values{}
	form.Set("login", "test")
	form.Set("password", "wrong")

	req, err := http.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	result := HandleLoginPage(ar, w, req)

	if result {
		t.Error("HandleLoginPage should return false for invalid password")
	}

	body := w.Body.String()
	if !strings.Contains(body, "<form") {
		t.Error("Expected login form in response body")
	}
	if !strings.Contains(body, "test-client") {
		t.Error("Expected client ID in response body")
	}
}

func TestHandleLoginPage_InvalidUsername(t *testing.T) {
	ar := newTestAuthorizeRequest("read")

	form := url.Values{}
	form.Set("login", "wrong")
	form.Set("password", "test")

	req, err := http.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	result := HandleLoginPage(ar, w, req)

	if result {
		t.Error("HandleLoginPage should return false for invalid username")
	}
}

func TestHandleLoginPage_GETRendersForm(t *testing.T) {
	ar := newTestAuthorizeRequest("read")

	req, err := http.NewRequest("GET", "/authorize?response_type=code&client_id=test-client", nil)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	result := HandleLoginPage(ar, w, req)

	if result {
		t.Error("HandleLoginPage should return false for GET request (render form)")
	}

	body := w.Body.String()
	if !strings.Contains(body, "LOGIN") {
		t.Error("Expected LOGIN label in form")
	}
	if !strings.Contains(body, "name=\"login\"") {
		t.Error("Expected login input field")
	}
	if !strings.Contains(body, "name=\"password\"") {
		t.Error("Expected password input field")
	}
}

func TestHandleLoginPage_EmptyCredentials(t *testing.T) {
	ar := newTestAuthorizeRequest("read")

	form := url.Values{}
	// login and password are both empty

	req, err := http.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	result := HandleLoginPage(ar, w, req)

	if result {
		t.Error("HandleLoginPage should return false for empty credentials")
	}
}

// --- HandleConsentPage tests ---

func TestHandleConsentPage_ApproveAllScopes(t *testing.T) {
	ar := newTestAuthorizeRequest("read write admin")

	form := url.Values{}
	form.Set("consent_submitted", "1")
	form.Add("scope", "read")
	form.Add("scope", "write")
	form.Add("scope", "admin")

	req, err := http.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	consented, approvedScopes := HandleConsentPage(ar, w, req)

	if !consented {
		t.Error("HandleConsentPage should return consented=true when consent_submitted=1")
	}

	if approvedScopes != "read write admin" {
		t.Errorf("Expected approved scopes 'read write admin', got %q", approvedScopes)
	}
}

func TestHandleConsentPage_ApproveSubsetOfScopes(t *testing.T) {
	ar := newTestAuthorizeRequest("read write admin")

	form := url.Values{}
	form.Set("consent_submitted", "1")
	form.Add("scope", "read")
	// "write" and "admin" not checked

	req, err := http.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	consented, approvedScopes := HandleConsentPage(ar, w, req)

	if !consented {
		t.Error("HandleConsentPage should return consented=true")
	}

	if approvedScopes != "read" {
		t.Errorf("Expected approved scopes 'read', got %q", approvedScopes)
	}
}

func TestHandleConsentPage_DenyAll(t *testing.T) {
	ar := newTestAuthorizeRequest("read write admin")

	form := url.Values{}
	form.Set("consent_submitted", "1")
	form.Set("deny_all", "1")

	req, err := http.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	consented, approvedScopes := HandleConsentPage(ar, w, req)

	if !consented {
		t.Error("HandleConsentPage should return consented=true even on deny")
	}

	if approvedScopes != "" {
		t.Errorf("Expected empty approved scopes on deny, got %q", approvedScopes)
	}
}

func TestHandleConsentPage_GETRendersConsentForm(t *testing.T) {
	ar := newTestAuthorizeRequest("read write admin")

	req, err := http.NewRequest("GET", "/authorize?response_type=code&client_id=test-client&scope=read+write+admin", nil)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	consented, approvedScopes := HandleConsentPage(ar, w, req)

	if consented {
		t.Error("HandleConsentPage should return consented=false for GET request")
	}

	if approvedScopes != "" {
		t.Errorf("Expected empty approved scopes when rendering form, got %q", approvedScopes)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Authorization Request") {
		t.Error("Expected 'Authorization Request' heading in consent form")
	}
	if !strings.Contains(body, "test-client") {
		t.Error("Expected client ID in consent form")
	}
	// Each requested scope should be a checkbox
	for _, scope := range []string{"read", "write", "admin"} {
		if !strings.Contains(body, fmt.Sprintf(`value="%s"`, scope)) {
			t.Errorf("Expected checkbox for scope %q in consent form", scope)
		}
	}
	if !strings.Contains(body, "Approve Selected") {
		t.Error("Expected 'Approve Selected' button in consent form")
	}
	if !strings.Contains(body, "Deny All") {
		t.Error("Expected 'Deny All' button in consent form")
	}
}

func TestHandleConsentPage_SingleScope(t *testing.T) {
	ar := newTestAuthorizeRequest("read")

	req, err := http.NewRequest("GET", "/authorize", nil)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	consented, approvedScopes := HandleConsentPage(ar, w, req)

	if consented {
		t.Error("HandleConsentPage should return consented=false for GET")
	}

	if approvedScopes != "" {
		t.Errorf("Expected empty approved scopes when rendering form, got %q", approvedScopes)
	}

	body := w.Body.String()
	if !strings.Contains(body, `value="read"`) {
		t.Error("Expected checkbox for 'read' scope")
	}
}

func TestHandleConsentPage_NoScopesSubmitted(t *testing.T) {
	ar := newTestAuthorizeRequest("read write")

	form := url.Values{}
	form.Set("consent_submitted", "1")
	// No scope checkboxes selected, no deny_all

	req, err := http.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	consented, approvedScopes := HandleConsentPage(ar, w, req)

	if !consented {
		t.Error("HandleConsentPage should return consented=true")
	}

	if approvedScopes != "" {
		t.Errorf("Expected empty approved scopes when no checkboxes selected, got %q", approvedScopes)
	}
}

func TestHandleConsentPage_POSTWithoutConsentSubmitted(t *testing.T) {
	ar := newTestAuthorizeRequest("read write")

	form := url.Values{}
	// consent_submitted is not set (simulates non-consent POST)

	req, err := http.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	consented, approvedScopes := HandleConsentPage(ar, w, req)

	if consented {
		t.Error("HandleConsentPage should return consented=false when consent_submitted is missing")
	}

	if approvedScopes != "" {
		t.Errorf("Expected empty approved scopes, got %q", approvedScopes)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Authorization Request") {
		t.Error("Expected consent form to be rendered")
	}
}

func TestHandleConsentPage_EmptyScope(t *testing.T) {
	// When ar.Scope is empty, the function falls back to []string{ar.Scope}
	ar := newTestAuthorizeRequest("")

	req, err := http.NewRequest("GET", "/authorize", nil)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	consented, _ := HandleConsentPage(ar, w, req)

	if consented {
		t.Error("HandleConsentPage should return consented=false for GET")
	}

	body := w.Body.String()
	// Should still render the form even with empty scope
	if !strings.Contains(body, "Authorization Request") {
		t.Error("Expected consent form to be rendered even with empty scope")
	}
}

func TestHandleConsentPage_DenyAllOverridesScopes(t *testing.T) {
	ar := newTestAuthorizeRequest("read write admin")

	form := url.Values{}
	form.Set("consent_submitted", "1")
	form.Set("deny_all", "1")
	// Even though scopes are checked, deny_all takes precedence
	form.Add("scope", "read")
	form.Add("scope", "write")

	req, err := http.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	consented, approvedScopes := HandleConsentPage(ar, w, req)

	if !consented {
		t.Error("HandleConsentPage should return consented=true")
	}

	if approvedScopes != "" {
		t.Errorf("Expected empty approved scopes when deny_all=1, got %q", approvedScopes)
	}
}

func TestHandleConsentPage_ConsentFormIncludesHiddenField(t *testing.T) {
	ar := newTestAuthorizeRequest("read")

	req, err := http.NewRequest("GET", "/authorize", nil)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	HandleConsentPage(ar, w, req)

	body := w.Body.String()
	if !strings.Contains(body, `name="consent_submitted"`) {
		t.Error("Expected hidden consent_submitted field in form")
	}
	if !strings.Contains(body, `value="1"`) {
		t.Error("Expected consent_submitted value of '1' in form")
	}
}

func TestHandleConsentPage_CheckboxesAreCheckedByDefault(t *testing.T) {
	ar := newTestAuthorizeRequest("read write")

	req, err := http.NewRequest("GET", "/authorize", nil)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	HandleConsentPage(ar, w, req)

	body := w.Body.String()
	// Verify checkboxes have the "checked" attribute
	if !strings.Contains(body, `checked`) {
		t.Error("Expected checkboxes to be checked by default")
	}
}
