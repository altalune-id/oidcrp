// Package oidcrptest runs a fake OpenID Provider for tests of oidcrp relying parties and oauthrs resource servers.
package oidcrptest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// User is who the fake upstream IdP signs in.
type User struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// IDP is a fake OpenID Provider: discovery, JWKS, a token endpoint that redeems the codes Authorize hands out, and RFC 7662 introspection.
type IDP struct {
	srv  *httptest.Server
	keys []signingKey
	t    testing.TB

	mu             sync.Mutex
	codes          map[string]grant
	opaque         map[string]map[string]any
	introspector   [2]string
	introspections int
	// User is who the next Authorize signs in.
	User User
	// Claims are merged over the ID token's claims, so a test can break one.
	Claims map[string]any
	// TokenStatus, when set, is the token endpoint's error status.
	TokenStatus int
	// Now is the upstream IdP's clock.
	Now func() time.Time
}

type signingKey struct {
	kid string
	key *rsa.PrivateKey
}

type grant struct {
	nonce    string
	clientID string
	user     User
}

// New starts a fake upstream IdP that closes with t.
func New(t testing.TB) *IDP {
	t.Helper()
	f := start(t)
	t.Cleanup(f.Close)
	return f
}

// Start runs a fake upstream IdP outside a test, such as in an example; it panics where New fails the test, and Close stops it.
func Start() *IDP { return start(nil) }

// Close stops the fake upstream IdP.
func (f *IDP) Close() { f.srv.Close() }

func start(t testing.TB) *IDP {
	f := &IDP{
		t: t, codes: map[string]grant{}, opaque: map[string]map[string]any{}, Now: time.Now,
		User: User{Subject: "110169484474386276334", Email: "ana@gmail.com", EmailVerified: true, Name: "Ana"},
	}
	f.RotateKey()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("GET /jwks", f.jwks)
	mux.HandleFunc("POST /token", f.token)
	mux.HandleFunc("POST /introspect", f.introspect)
	f.srv = httptest.NewTLSServer(mux)
	return f
}

func (f *IDP) fatal(err error) {
	if f.t != nil {
		f.t.Helper()
		f.t.Fatal(err)
	}
	panic(err)
}

// Issuer is the upstream IdP's issuer URL.
func (f *IDP) Issuer() string { return f.srv.URL }

// Client is an HTTP client that trusts the upstream IdP's test certificate.
func (f *IDP) Client() *http.Client { return f.srv.Client() }

// Authorize plays the browser at the authorization URL: it signs User in and returns the redirect's query.
func (f *IDP) Authorize(authURL string) url.Values {
	if f.t != nil {
		f.t.Helper()
	}
	u, err := url.Parse(authURL)
	if err != nil {
		f.fatal(err)
	}
	q := u.Query()
	code := rand.Text()
	f.mu.Lock()
	f.codes[code] = grant{nonce: q.Get("nonce"), clientID: q.Get("client_id"), user: f.User}
	f.mu.Unlock()
	return url.Values{"code": {code}, "state": {q.Get("state")}, "iss": {f.Issuer()}}
}

// Deny returns the redirect's query of a person who cancelled at the upstream IdP.
func (f *IDP) Deny(authURL string) url.Values {
	u, _ := url.Parse(authURL)
	return url.Values{"error": {"access_denied"}, "state": {u.Query().Get("state")}, "iss": {f.Issuer()}}
}

func (f *IDP) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer": f.Issuer(), "authorization_endpoint": f.Issuer() + "/authorize", "token_endpoint": f.Issuer() + "/token",
		"jwks_uri": f.Issuer() + "/jwks", "code_challenge_methods_supported": []string{"S256"},
		"authorization_response_iss_parameter_supported": true, "id_token_signing_alg_values_supported": []string{"RS256"},
		"introspection_endpoint": f.Issuer() + "/introspect",
	})
}

func (f *IDP) jwks(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	set := jose.JSONWebKeySet{}
	for _, k := range f.keys {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: &k.key.PublicKey, KeyID: k.kid, Algorithm: "RS256", Use: "sig"})
	}
	f.mu.Unlock()
	writeJSON(w, set)
}

// RotateKey publishes a new signing key next to the old ones and signs every later token with it.
func (f *IDP) RotateKey() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = append(f.keys, signingKey{kid: fmt.Sprintf("k%d", len(f.keys)+1), key: key})
}

// AccessToken signs an RFC 9068 access token (typ at+jwt) for User; claims are merged over the defaults, and nil deletes one.
func (f *IDP) AccessToken(claims map[string]any) string {
	return f.signTyped("at+jwt", f.AccessTokenClaims(claims))
}

// AccessTokenClaims are the claims AccessToken signs, for a test that signs them itself.
func (f *IDP) AccessTokenClaims(claims map[string]any) map[string]any {
	now := f.Now()
	base := map[string]any{
		"iss": f.Issuer(), "sub": f.User.Subject, "client_id": "test-client", "iat": now.Unix(), "exp": now.Add(15 * time.Minute).Unix(),
		"jti": rand.Text(), "scope": "openid",
	}
	return merge(base, claims)
}

// IDToken signs an ID token (typ JWT) with claims, to prove a resource server refuses one as an access token.
func (f *IDP) IDToken(claims map[string]any) string {
	return f.signTyped("JWT", claims)
}

// Introspector sets the credentials the introspection endpoint accepts (client_secret_basic).
func (f *IDP) Introspector(clientID, secret string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.introspector = [2]string{clientID, secret}
}

// Opaque registers an opaque token; introspecting it answers active with claims, and an unknown token answers inactive.
func (f *IDP) Opaque(token string, claims map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opaque[token] = claims
}

// Revoke makes an opaque token inactive.
func (f *IDP) Revoke(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.opaque, token)
}

// Introspections counts the introspection requests that authenticated.
func (f *IDP) Introspections() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.introspections
}

func (f *IDP) introspect(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, secret, ok := r.BasicAuth()
	if !ok || f.introspector[0] == "" || id != f.introspector[0] || secret != f.introspector[1] {
		w.Header().Set("WWW-Authenticate", `Basic realm="introspect"`)
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]string{"error": "invalid_client"})
		return
	}
	f.introspections++
	claims, known := f.opaque[r.PostFormValue("token")]
	if !known {
		writeJSON(w, map[string]any{"active": false})
		return
	}
	writeJSON(w, merge(map[string]any{"active": true, "iss": f.Issuer(), "token_type": "Bearer"}, claims))
}

func merge(base, over map[string]any) map[string]any {
	for k, v := range over {
		if v == nil {
			delete(base, k)
			continue
		}
		base[k] = v
	}
	return base
}

func (f *IDP) token(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	g, ok := f.codes[r.PostFormValue("code")]
	delete(f.codes, r.PostFormValue("code"))
	if f.TokenStatus != 0 || !ok || r.PostFormValue("code_verifier") == "" {
		w.WriteHeader(max(f.TokenStatus, http.StatusBadRequest))
		writeJSON(w, map[string]string{"error": "invalid_grant"})
		return
	}
	now := f.Now()
	claims := map[string]any{
		"iss": f.Issuer(), "sub": g.user.Subject, "aud": g.clientID, "azp": g.clientID, "exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(), "nonce": g.nonce, "email": g.user.Email, "email_verified": g.user.EmailVerified, "name": g.user.Name,
	}
	maps.Copy(claims, f.Claims)
	writeJSON(w, map[string]any{"access_token": "upstream-at", "token_type": "Bearer", "id_token": f.sign(claims)})
}

func (f *IDP) sign(claims map[string]any) string {
	return f.signTypedLocked("JWT", claims)
}

func (f *IDP) signTyped(typ string, claims map[string]any) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.signTypedLocked(typ, claims)
}

func (f *IDP) signTypedLocked(typ string, claims map[string]any) string {
	k := f.keys[len(f.keys)-1]
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(strings.TrimSpace(typ))).WithHeader("kid", k.kid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: k.key}, opts)
	if err != nil {
		f.fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		f.fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		f.fatal(err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		f.fatal(err)
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
