package main

// PKCE (Proof Key for Code Exchange) Demo - RFC 7636
//
// This example demonstrates the OAuth2 Authorization Code flow with PKCE,
// which is designed for public clients (mobile apps, SPAs) that cannot
// securely store client secrets.
//
// Open url in browser:
// http://localhost:14000/app
//
// PKCE Flow:
//  1. Client generates a random code_verifier
//  2. Client derives a code_challenge from the verifier (using SHA256)
//  3. Client sends code_challenge with the authorization request
//  4. Server stores the code_challenge alongside the authorization code
//  5. Client sends the original code_verifier with the token exchange request
//  6. Server verifies that SHA256(code_verifier) == code_challenge
//
// This prevents authorization code interception attacks because an attacker
// who intercepts the authorization code cannot exchange it without the
// original code_verifier.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"github.com/openshift/osin"
	"github.com/openshift/osin/example"
)

const (
	// codeVerifierLength is the number of random bytes used to generate
	// the PKCE code verifier. 32 bytes produces a 43-character base64url
	// string, which is the minimum length allowed by RFC 7636.
	codeVerifierLength = 32
)

// generateCodeVerifier creates a cryptographically random code verifier
// as specified in RFC 7636 Section 4.1.
// The verifier is a high-entropy random string using unreserved characters
// [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~", with a minimum length
// of 43 characters and a maximum length of 128 characters.
func generateCodeVerifier() (string, error) {
	buf := make([]byte, codeVerifierLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	// base64url encoding without padding produces a 43-character string
	// from 32 bytes, satisfying the RFC 7636 minimum length requirement
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// generateCodeChallenge derives a code challenge from the code verifier
// using the S256 method as specified in RFC 7636 Section 4.2:
//
//	code_challenge = BASE64URL(SHA256(code_verifier))
//
// The S256 method is preferred over "plain" because it prevents the
// code_challenge from being used to derive the code_verifier.
func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func main() {
	// Configure the OAuth2 server
	cfg := osin.NewServerConfig()
	cfg.AllowGetAccessRequest = true
	cfg.AllowClientSecretInParams = true

	// RequirePKCEForPublicClients enforces PKCE for clients with an
	// empty secret, which is the recommended configuration for servers
	// that support public clients.
	cfg.RequirePKCEForPublicClients = true

	storage := example.NewTestStorage()

	// Register a public client (no secret) to demonstrate PKCE.
	// Public clients cannot securely store secrets, so they rely on
	// PKCE to protect the authorization code exchange.
	storage.SetClient("pkce-client", &osin.DefaultClient{
		Id:          "pkce-client",
		Secret:      "",
		RedirectUri: "http://localhost:14000/appauth/code",
	})

	server := osin.NewServer(cfg, storage)

	// Generate PKCE parameters once at startup for this demo.
	// In a real application, a fresh code_verifier MUST be generated
	// for each authorization request.
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		panic(fmt.Sprintf("Failed to generate code verifier: %v", err))
	}
	codeChallenge := generateCodeChallenge(codeVerifier)

	fmt.Println("=== PKCE Demo ===")
	fmt.Printf("Code Verifier:  %s\n", codeVerifier)
	fmt.Printf("Code Challenge: %s\n", codeChallenge)
	fmt.Printf("Method:         S256\n")
	fmt.Println()

	// Authorization code endpoint
	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {
			if !example.HandleLoginPage(ar, w, r) {
				return
			}
			ar.UserData = struct{ Login string }{Login: "test"}
			ar.Authorized = true
			server.FinishAuthorizeRequest(resp, r, ar)
		}
		if resp.IsError && resp.InternalError != nil {
			fmt.Printf("ERROR: %s\n", resp.InternalError)
		}
		osin.OutputJSON(resp, w, r)
	})

	// Access token endpoint
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ar := server.HandleAccessRequest(resp, r); ar != nil {
			ar.Authorized = true
			server.FinishAccessRequest(resp, r, ar)
		}
		if resp.IsError && resp.InternalError != nil {
			fmt.Printf("ERROR: %s\n", resp.InternalError)
		}
		osin.OutputJSON(resp, w, r)
	})

	// Information endpoint
	http.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ir := server.HandleInfoRequest(resp, r); ir != nil {
			server.FinishInfoRequest(resp, r, ir)
		}
		osin.OutputJSON(resp, w, r)
	})

	// Application home endpoint - shows both PKCE and standard auth links
	http.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>"))
		w.Write([]byte("<h1>PKCE (RFC 7636) Demo</h1>"))

		// PKCE authorization link for the public client.
		// Note: code_challenge and code_challenge_method are included
		// in the authorization request, but code_verifier is NOT sent here.
		// The verifier is only sent during the token exchange (step 2).
		pkceAuthURL := fmt.Sprintf(
			"/authorize?response_type=code&client_id=pkce-client&state=pkce-state&scope=everything&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256",
			url.QueryEscape("http://localhost:14000/appauth/code"),
			url.QueryEscape(codeChallenge),
		)
		w.Write([]byte("<h2>Public Client with PKCE (Recommended for Mobile/SPA)</h2>"))
		w.Write([]byte("<p>This flow uses a public client (no secret) protected by PKCE:</p>"))
		w.Write([]byte("<ol>"))
		w.Write([]byte("<li>Authorization request includes <code>code_challenge</code> (SHA256 hash of verifier)</li>"))
		w.Write([]byte("<li>Token exchange includes <code>code_verifier</code> (original random string)</li>"))
		w.Write([]byte("<li>Server verifies: <code>SHA256(code_verifier) == code_challenge</code></li>"))
		w.Write([]byte("</ol>"))
		w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Login with PKCE (S256)</a><br/><br/>", pkceAuthURL)))

		// Standard authorization link (for comparison)
		stdAuthURL := fmt.Sprintf(
			"/authorize?response_type=code&client_id=1234&state=xyz&scope=everything&redirect_uri=%s",
			url.QueryEscape("http://localhost:14000/appauth/code"),
		)
		w.Write([]byte("<h2>Confidential Client without PKCE (Standard Flow)</h2>"))
		w.Write([]byte("<p>This flow uses a confidential client with a client secret (no PKCE):</p>"))
		w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Login without PKCE</a><br/>", stdAuthURL)))

		// Display the PKCE parameters for educational purposes
		w.Write([]byte("<h2>PKCE Parameters (for this demo session)</h2>"))
		w.Write([]byte("<table border=\"1\" cellpadding=\"8\">"))
		w.Write([]byte("<tr><td><strong>code_verifier</strong></td><td><code>" + codeVerifier + "</code></td></tr>"))
		w.Write([]byte("<tr><td><strong>code_challenge</strong></td><td><code>" + codeChallenge + "</code></td></tr>"))
		w.Write([]byte("<tr><td><strong>code_challenge_method</strong></td><td><code>S256</code></td></tr>"))
		w.Write([]byte("</table>"))
		w.Write([]byte("<p><em>In production, a fresh code_verifier must be generated for each authorization request.</em></p>"))

		w.Write([]byte("</body></html>"))
	})

	// Application destination - handles the authorization code callback
	http.HandleFunc("/appauth/code", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		code := r.FormValue("code")
		state := r.FormValue("state")
		isPKCE := state == "pkce-state"

		w.Write([]byte("<html><body>"))
		w.Write([]byte("<h1>Authorization Code Callback</h1>"))
		defer w.Write([]byte("</body></html>"))

		if code == "" {
			w.Write([]byte("Nothing to do"))
			return
		}

		w.Write([]byte(fmt.Sprintf("<p><strong>Authorization Code:</strong> <code>%s</code></p>", code)))
		w.Write([]byte(fmt.Sprintf("<p><strong>State:</strong> <code>%s</code></p>", state)))
		w.Write([]byte(fmt.Sprintf("<p><strong>PKCE Flow:</strong> %t</p>", isPKCE)))

		jr := make(map[string]interface{})

		// Build the token exchange URL.
		// For PKCE: include code_verifier, use public client (no secret).
		// For standard: include client_secret, use confidential client.
		var tokenURL string
		if isPKCE {
			// PKCE token exchange: the code_verifier is sent here.
			// The server will verify SHA256(code_verifier) == stored code_challenge.
			// Note: No client_secret is needed for public clients.
			tokenURL = fmt.Sprintf(
				"/token?grant_type=authorization_code&client_id=pkce-client&state=pkce-state&redirect_uri=%s&code=%s&code_verifier=%s",
				url.QueryEscape("http://localhost:14000/appauth/code"),
				url.QueryEscape(code),
				url.QueryEscape(codeVerifier),
			)
		} else {
			// Standard token exchange with client secret
			tokenURL = fmt.Sprintf(
				"/token?grant_type=authorization_code&client_id=1234&client_secret=aabbccdd&state=xyz&redirect_uri=%s&code=%s",
				url.QueryEscape("http://localhost:14000/appauth/code"),
				url.QueryEscape(code),
			)
		}

		// Auto-parse mode: automatically exchange the code for a token
		if r.FormValue("doparse") == "1" {
			var auth *osin.BasicAuth
			if isPKCE {
				// Public client: use empty secret for basic auth
				auth = &osin.BasicAuth{Username: "pkce-client", Password: ""}
			} else {
				// Confidential client: use client secret
				auth = &osin.BasicAuth{Username: "1234", Password: "aabbccdd"}
			}

			err := example.DownloadAccessToken(
				fmt.Sprintf("http://localhost:14000%s", tokenURL),
				auth, jr,
			)
			if err != nil {
				w.Write([]byte(fmt.Sprintf("<p style=\"color:red\">Error: %s</p>", err.Error())))
			}
		}

		// Show JSON error
		if erd, ok := jr["error"]; ok {
			w.Write([]byte(fmt.Sprintf("<p style=\"color:red\"><strong>ERROR:</strong> %s</p>\n", erd)))
			if desc, ok := jr["error_description"]; ok {
				w.Write([]byte(fmt.Sprintf("<p style=\"color:red\">%s</p>\n", desc)))
			}
		}

		// Show access token
		if at, ok := jr["access_token"]; ok {
			w.Write([]byte(fmt.Sprintf("<p style=\"color:green\"><strong>ACCESS TOKEN:</strong> %s</p>\n", at)))
		}

		w.Write([]byte(fmt.Sprintf("<p><strong>Full Result:</strong> %+v</p>\n", jr)))

		// Output navigation links
		if isPKCE {
			w.Write([]byte("<h2>PKCE Token Exchange</h2>"))
			w.Write([]byte("<p>The token request below includes the <code>code_verifier</code> parameter. "))
			w.Write([]byte("The server will verify: <code>SHA256(code_verifier) == code_challenge</code></p>"))
		}

		w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Goto Token URL (raw)</a><br/>", tokenURL)))

		cururl := *r.URL
		curq := cururl.Query()
		curq.Set("doparse", "1")
		cururl.RawQuery = curq.Encode()
		w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Exchange Code for Token</a><br/>", cururl.String())))

		if rt, ok := jr["refresh_token"]; ok {
			rurl := fmt.Sprintf("/appauth/refresh?code=%s", rt)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Refresh Token</a><br/>", rurl)))
		}

		if at, ok := jr["access_token"]; ok {
			rurl := fmt.Sprintf("/appauth/info?code=%s", at)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Token Info</a><br/>", rurl)))
		}

		// Link back to start
		w.Write([]byte("<br/><a href=\"/app\">Back to Home</a>"))
	})

	// Refresh token endpoint
	http.HandleFunc("/appauth/refresh", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		w.Write([]byte("<html><body>"))
		w.Write([]byte("<h1>Refresh Token</h1>"))
		defer w.Write([]byte("</body></html>"))

		code := r.FormValue("code")
		if code == "" {
			w.Write([]byte("Nothing to do"))
			return
		}

		jr := make(map[string]interface{})

		// Build refresh token URL
		refreshURL := fmt.Sprintf("/token?grant_type=refresh_token&refresh_token=%s",
			url.QueryEscape(code))

		// Download token
		err := example.DownloadAccessToken(
			fmt.Sprintf("http://localhost:14000%s", refreshURL),
			&osin.BasicAuth{Username: "1234", Password: "aabbccdd"}, jr,
		)
		if err != nil {
			w.Write([]byte(fmt.Sprintf("<p style=\"color:red\">Error: %s</p>", err.Error())))
		}

		// Show JSON error
		if erd, ok := jr["error"]; ok {
			w.Write([]byte(fmt.Sprintf("<p style=\"color:red\"><strong>ERROR:</strong> %s</p>\n", erd)))
		}

		// Show access token
		if at, ok := jr["access_token"]; ok {
			w.Write([]byte(fmt.Sprintf("<p style=\"color:green\"><strong>ACCESS TOKEN:</strong> %s</p>\n", at)))
		}

		w.Write([]byte(fmt.Sprintf("<p><strong>Full Result:</strong> %+v</p>\n", jr)))

		if rt, ok := jr["refresh_token"]; ok {
			rurl := fmt.Sprintf("/appauth/refresh?code=%s", rt)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Refresh Token Again</a><br/>", rurl)))
		}

		if at, ok := jr["access_token"]; ok {
			rurl := fmt.Sprintf("/appauth/info?code=%s", at)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Token Info</a><br/>", rurl)))
		}

		w.Write([]byte("<br/><a href=\"/app\">Back to Home</a>"))
	})

	// Token info endpoint
	http.HandleFunc("/appauth/info", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		w.Write([]byte("<html><body>"))
		w.Write([]byte("<h1>Token Info</h1>"))
		defer w.Write([]byte("</body></html>"))

		code := r.FormValue("code")
		if code == "" {
			w.Write([]byte("Nothing to do"))
			return
		}

		jr := make(map[string]interface{})

		// Build info URL
		infoURL := fmt.Sprintf("/info?code=%s", url.QueryEscape(code))

		// Download info
		err := example.DownloadAccessToken(
			fmt.Sprintf("http://localhost:14000%s", infoURL),
			&osin.BasicAuth{Username: "1234", Password: "aabbccdd"}, jr,
		)
		if err != nil {
			w.Write([]byte(fmt.Sprintf("<p style=\"color:red\">Error: %s</p>", err.Error())))
		}

		// Show JSON error
		if erd, ok := jr["error"]; ok {
			w.Write([]byte(fmt.Sprintf("<p style=\"color:red\"><strong>ERROR:</strong> %s</p>\n", erd)))
		}

		w.Write([]byte(fmt.Sprintf("<p><strong>Full Result:</strong> %+v</p>\n", jr)))

		w.Write([]byte("<br/><a href=\"/app\">Back to Home</a>"))
	})

	fmt.Println("PKCE Demo Server running on http://localhost:14000/app")
	fmt.Println("Use test/test as login credentials")
	http.ListenAndServe(":14000", nil)
}
