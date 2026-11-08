package oidcrp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeAS struct {
	srv      *httptest.Server
	mu       sync.Mutex
	hits     map[string]int
	oauth    int
	oidc     int
	issuer   string
	oidcJWKS bool
	form     url.Values
}

const asPath = "/p/acme"

func newFakeAS(t *testing.T) *fakeAS {
	t.Helper()
	f := &fakeAS{hits: map[string]int{}, oidcJWKS: true}
	doc := func(jwks bool) map[string]any {
		iss := f.srv.URL + asPath
		if f.issuer != "" {
			iss = f.issuer
		}
		out := map[string]any{
			"issuer": iss, "authorization_endpoint": f.srv.URL + asPath + "/authorize", "token_endpoint": f.srv.URL + asPath + "/token",
			"code_challenge_methods_supported": []string{"S256"}, "authorization_response_iss_parameter_supported": true,
		}
		if jwks {
			out["jwks_uri"] = f.srv.URL + asPath + "/jwks"
		}
		return out
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hits[r.URL.Path]++
		oauth, oidc := f.oauth, f.oidc
		f.mu.Unlock()
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server" + asPath:
			if oauth != 0 {
				w.WriteHeader(oauth)
				return
			}
			_ = json.NewEncoder(w).Encode(doc(false))
		case asPath + "/.well-known/openid-configuration":
			if oidc != 0 {
				w.WriteHeader(oidc)
				return
			}
			_ = json.NewEncoder(w).Encode(doc(f.oidcJWKS))
		case asPath + "/token":
			require.NoError(t, r.ParseForm())
			f.mu.Lock()
			f.form = r.PostForm
			f.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "at-1", "token_type": "Bearer", "refresh_token": "rt-1", "expires_in": 600, "id_token": "not.a.jwt",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAS) client(oauthMetadata bool) *Client {
	return New(Config{
		Issuer: f.srv.URL + asPath, ClientID: "oagent", RedirectURI: "https://oagent.example/oauth/callback",
		Scopes: []string{"mcp:tools"}, Resource: "https://notes.example/mcp", OAuthMetadata: oauthMetadata,
	}).WithClock(func() time.Time { return now })
}

func (f *fakeAS) hitsOf(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

func TestAuthorizationServerMetadataURL(t *testing.T) {
	for issuer, want := range map[string]string{
		"https://as.example":           "https://as.example/.well-known/oauth-authorization-server",
		"https://as.example/":          "https://as.example/.well-known/oauth-authorization-server",
		"https://as.example/p/acme":    "https://as.example/.well-known/oauth-authorization-server/p/acme",
		"https://as.example/p/acme/":   "https://as.example/.well-known/oauth-authorization-server/p/acme",
		"http://127.0.0.1:8080/tenant": "http://127.0.0.1:8080/.well-known/oauth-authorization-server/tenant",
	} {
		assert.Equal(t, want, authorizationServerMetadataURL(issuer), "RFC 8414 §3.1: %s", issuer)
	}
}

func TestOAuthMetadata_Discovery(t *testing.T) {
	oauthPath, oidcPath := "/.well-known/oauth-authorization-server"+asPath, asPath+"/.well-known/openid-configuration"

	f := newFakeAS(t)
	meta, err := f.client(true).Keys().Metadata(t.Context())
	require.NoError(t, err, "RFC 8414 §2: jwks_uri is optional in authorization server metadata")
	assert.Equal(t, f.srv.URL+asPath+"/token", meta.TokenEndpoint)
	assert.Equal(t, 1, f.hitsOf(oauthPath), "RFC 8414 §3.1: the path-inserted well-known URL")
	assert.Zero(t, f.hitsOf(oidcPath), "a published RFC 8414 document needs no OIDC discovery")

	f = newFakeAS(t)
	f.oauth = http.StatusNotFound
	_, err = f.client(true).Keys().Metadata(t.Context())
	require.NoError(t, err, "RFC 8414 §3.2: no document, so OIDC discovery is tried")
	assert.Equal(t, 1, f.hitsOf(oidcPath))

	for name, tweak := range map[string]func(*fakeAS){
		"another issuer":  func(f *fakeAS) { f.issuer = "https://another.example" + asPath },
		"a server error":  func(f *fakeAS) { f.oauth = http.StatusInternalServerError },
		"an unauthorized": func(f *fakeAS) { f.oauth = http.StatusUnauthorized },
	} {
		f = newFakeAS(t)
		tweak(f)
		_, err = f.client(true).Keys().Metadata(t.Context())
		assert.Error(t, err, name)
		assert.Zero(t, f.hitsOf(oidcPath), "RFC 8414 §3.3: %s fails closed with no fallback", name)
	}
	f = newFakeAS(t)
	f.issuer = "https://another.example" + asPath
	_, err = f.client(true).Keys().Metadata(t.Context())
	assert.Equal(t, ReasonMisconfigured, ReasonOf(err), "RFC 8414 §3.3: the issuer must be identical")

	f = newFakeAS(t)
	_, err = f.client(false).Keys().Metadata(t.Context())
	require.NoError(t, err)
	assert.Zero(t, f.hitsOf(oauthPath), "without OAuthMetadata, OIDC discovery only, as before")
	assert.Equal(t, 1, f.hitsOf(oidcPath))

	f = newFakeAS(t)
	f.oauth, f.oidcJWKS = http.StatusNotFound, false
	_, err = f.client(true).Keys().Metadata(t.Context())
	assert.Equal(t, ReasonDiscovery, ReasonOf(err), "OIDC Discovery §3: an OIDC document still needs jwks_uri")
}

func TestOAuthMetadata_GrantKeepsResourceAndIssuer(t *testing.T) {
	f := newFakeAS(t)
	c := f.client(true)
	req, err := NewAuthRequest("consent", "")
	require.NoError(t, err)
	raw, err := c.AuthCodeURL(t.Context(), req)
	require.NoError(t, err)
	u, err := url.Parse(raw)
	require.NoError(t, err)
	assert.Equal(t, f.srv.URL+asPath+"/authorize", u.Scheme+"://"+u.Host+u.Path, "the authorization endpoint from RFC 8414 metadata")
	assert.Equal(t, "https://notes.example/mcp", u.Query().Get("resource"), "RFC 8707 §2.1")

	_, err = c.ExchangeTokens(t.Context(), Callback{Code: "c1", State: req.State, Issuer: "https://evil.example"}, req)
	assert.Equal(t, ReasonIssuer, ReasonOf(err), "RFC 9207 §2.4: iss names the authorization server")

	set, err := c.ExchangeTokens(t.Context(), Callback{Code: "c1", State: req.State, Issuer: f.srv.URL + asPath}, req)
	require.NoError(t, err)
	assert.Equal(t, &TokenSet{AccessToken: "at-1", RefreshToken: "rt-1", ExpiresAt: now.Add(600 * time.Second), Scopes: []string{"mcp:tools"}}, set,
		"RFC 6749 §5.1: no openid, so the id_token is not read")
	assert.Equal(t, "https://notes.example/mcp", f.form.Get("resource"), "RFC 8707 §2.2: on the code request")
	assert.Equal(t, "authorization_code", f.form.Get("grant_type"))

	_, err = c.Refresh(t.Context(), *set)
	require.NoError(t, err)
	assert.Equal(t, "https://notes.example/mcp", f.form.Get("resource"), "RFC 8707 §2.2: on the refresh request")
}
