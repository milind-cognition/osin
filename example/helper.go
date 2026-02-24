package example

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/openshift/osin"
)

func HandleLoginPage(ar *osin.AuthorizeRequest, w http.ResponseWriter, r *http.Request) bool {
	r.ParseForm()
	if r.Method == "POST" && r.FormValue("login") == "test" && r.FormValue("password") == "test" {
		return true
	}

	w.Write([]byte("<html><body>"))

	w.Write([]byte(fmt.Sprintf("LOGIN %s (use test/test)<br/>", ar.Client.GetId())))
	w.Write([]byte(fmt.Sprintf("<form action=\"/authorize?%s\" method=\"POST\">", r.URL.RawQuery)))

	w.Write([]byte("Login: <input type=\"text\" name=\"login\" /><br/>"))
	w.Write([]byte("Password: <input type=\"password\" name=\"password\" /><br/>"))
	w.Write([]byte("<input type=\"submit\"/>"))

	w.Write([]byte("</form>"))

	w.Write([]byte("</body></html>"))

	return false
}

// HandleConsentPage displays a consent screen showing requested scopes with
// checkboxes so the user can approve or deny individual scopes. It returns
// (true, approvedScopes) when the user submits the form, or (false, "") when
// the consent page is rendered (waiting for input).
func HandleConsentPage(ar *osin.AuthorizeRequest, w http.ResponseWriter, r *http.Request) (bool, string) {
	r.ParseForm()
	if r.Method == "POST" && r.FormValue("consent_submitted") == "1" {
		if r.FormValue("deny_all") == "1" {
			return true, ""
		}
		// Use PostForm to read only POST body values, avoiding collision
		// with the scope parameter in the URL query string.
		approved := r.PostForm["approved_scope"]
		return true, strings.Join(approved, " ")
	}

	// Parse requested scopes (space-separated per OAuth2 spec)
	requestedScopes := strings.Fields(ar.Scope)
	if len(requestedScopes) == 0 {
		requestedScopes = []string{ar.Scope}
	}

	w.Write([]byte(`<html><head><style>
		body { font-family: sans-serif; max-width: 600px; margin: 40px auto; }
		.scope-item { padding: 8px 0; border-bottom: 1px solid #eee; }
		.scope-item label { cursor: pointer; }
		.btn { padding: 8px 20px; margin: 4px; cursor: pointer; border: 1px solid #ccc; border-radius: 4px; }
		.btn-approve { background: #4CAF50; color: white; border-color: #4CAF50; }
		.btn-deny { background: #f44336; color: white; border-color: #f44336; }
		h2 { color: #333; }
		.client-info { background: #f5f5f5; padding: 12px; border-radius: 4px; margin-bottom: 16px; }
	</style></head><body>`))

	w.Write([]byte("<h2>Authorization Request</h2>"))
	w.Write([]byte(fmt.Sprintf(`<div class="client-info"><strong>%s</strong> is requesting access to your account.</div>`, ar.Client.GetId())))
	w.Write([]byte("<h3>Requested Permissions:</h3>"))

	w.Write([]byte(fmt.Sprintf(`<form action="/authorize?%s" method="POST">`, r.URL.RawQuery)))
	w.Write([]byte(`<input type="hidden" name="consent_submitted" value="1"/>`))

	// Forward login credentials so HandleLoginPage succeeds on the consent POST
	w.Write([]byte(fmt.Sprintf(`<input type="hidden" name="login" value="%s"/>`, r.FormValue("login"))))
	w.Write([]byte(fmt.Sprintf(`<input type="hidden" name="password" value="%s"/>`, r.FormValue("password"))))

	for _, scope := range requestedScopes {
		w.Write([]byte(fmt.Sprintf(`<div class="scope-item"><label><input type="checkbox" name="approved_scope" value="%s" checked/> %s</label></div>`, scope, scope)))
	}

	w.Write([]byte(`<br/><input type="submit" class="btn btn-approve" value="Approve Selected"/>`))
	w.Write([]byte(`<button type="submit" class="btn btn-deny" name="deny_all" value="1">Deny All</button>`))

	w.Write([]byte("</form>"))
	w.Write([]byte("</body></html>"))

	return false, ""
}

func DownloadAccessToken(url string, auth *osin.BasicAuth, output map[string]interface{}) error {
	// download access token
	preq, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}
	if auth != nil {
		preq.SetBasicAuth(auth.Username, auth.Password)
	}

	pclient := &http.Client{}
	presp, err := pclient.Do(preq)
	if err != nil {
		return err
	}
	defer presp.Body.Close()

	if presp.StatusCode != 200 {
		return errors.New("Invalid status code")
	}

	jdec := json.NewDecoder(presp.Body)
	err = jdec.Decode(&output)
	return err
}
