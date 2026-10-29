package oidcrp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeIDP struct {
	t        *testing.T
	srv      *httptest.Server
	key      *rsa.PrivateKey
	kid      string
	mu       sync.Mutex
	claims   map[string]any
	header   map[jose.HeaderKey]any
	alg      jose.SignatureAlgorithm
	noS256   bool
	iss      string
	tokenErr int
	errBody  string
	noIDTok  bool
	form     url.Values
	user     string
	pass     string
	basic    bool
	jwksHits int
	slow     time.Duration
	algs     []string
	keyAlg   string
	jwksCode int
	jwksGate chan struct{}
	maxAge   string
	metaHits int
	tokType  string
	endSess  string
	lastID   string
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	f := &fakeIDP{t: t, key: key, kid: "k1", alg: jose.RS256, algs: []string{"RS256"}, keyAlg: "RS256"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		methods := []string{"S256"}
		if f.noS256 {
			methods = []string{"plain"}
		}
		iss := f.srv.URL
		if f.iss != "" {
			iss = f.iss
		}
		f.mu.Lock()
		f.metaHits++
		f.mu.Unlock()
		if f.maxAge != "" {
			w.Header().Set("Cache-Control", f.maxAge)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": iss, "authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token",
			"jwks_uri": f.srv.URL + "/jwks", "code_challenge_methods_supported": methods,
			"authorization_response_iss_parameter_supported": true, "id_token_signing_alg_values_supported": f.algs,
			"end_session_endpoint": f.endSess,
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		f.jwksHits++
		kid, code, gate, keyAlg := f.kid, f.jwksCode, f.jwksGate, f.keyAlg
		f.mu.Unlock()
		if gate != nil {
			<-gate
		}
		if code != 0 {
			w.WriteHeader(code)
			return
		}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: kid, Algorithm: keyAlg, Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(f.slow)
		require.NoError(t, r.ParseForm())
		f.form = r.PostForm
		f.user, f.pass, f.basic = r.BasicAuth()
		if f.tokenErr != 0 {
			w.WriteHeader(f.tokenErr)
			body := `{"error":"invalid_grant"}`
			if f.errBody != "" {
				body = f.errBody
			}
			_, _ = w.Write([]byte(body))
			return
		}
		typ := "Bearer"
		if f.tokType != "" {
			typ = f.tokType
		}
		out := map[string]any{"access_token": "upstream-at", "token_type": typ, "refresh_token": "upstream-rt"}
		if !f.noIDTok {
			f.lastID = f.sign()
			out["id_token"] = f.lastID
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIDP) sign() string {
	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1")
	for k, v := range f.header {
		opts = opts.WithHeader(k, v)
	}
	var key any = f.key
	if f.alg == jose.HS256 {
		key = []byte("a-shared-secret-of-thirty-two-b!")
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: f.alg, Key: key}, opts)
	require.NoError(f.t, err)
	payload, err := json.Marshal(f.claims)
	require.NoError(f.t, err)
	obj, err := signer.Sign(payload)
	require.NoError(f.t, err)
	out, err := obj.CompactSerialize()
	require.NoError(f.t, err)
	return out
}

var now = time.Unix(1_800_000_000, 0)

func (f *fakeIDP) client() *Client {
	return New(Config{
		Issuer: f.srv.URL, ClientID: "cid.apps", ClientSecret: "s3cret/+=", RedirectURI: "https://othra.example/p/acme/federation/google/callback",
		Scopes: []string{"openid", "email", "profile"}, AcceptIssuers: []string{"idp.example"},
	}).WithClock(func() time.Time { return now })
}

func (f *fakeIDP) goodClaims(nonce string) map[string]any {
	return map[string]any{
		"iss": f.srv.URL, "sub": "1234567890", "aud": "cid.apps", "azp": "cid.apps", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"nonce": nonce, "email": "ana@gmail.com", "email_verified": true, "name": "Ana", "hd": "",
	}
}

func TestAuthCodeURL(t *testing.T) {
	f := newFakeIDP(t)
	req, err := NewAuthRequest("select_account", "ana@gmail.com")
	require.NoError(t, err)
	assert.Len(t, req.State, 43)
	raw, err := f.client().AuthCodeURL(context.Background(), req)
	require.NoError(t, err)
	u, err := url.Parse(raw)
	require.NoError(t, err)
	q := u.Query()
	sum := sha256.Sum256([]byte(req.CodeVerifier))
	assert.Equal(t, f.srv.URL+"/authorize", u.Scheme+"://"+u.Host+u.Path)
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Equal(t, "cid.apps", q.Get("client_id"))
	assert.Equal(t, "openid email profile", q.Get("scope"))
	assert.Equal(t, req.State, q.Get("state"))
	assert.Equal(t, req.Nonce, q.Get("nonce"))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), q.Get("code_challenge"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.Equal(t, "select_account", q.Get("prompt"))
	assert.Equal(t, "ana@gmail.com", q.Get("login_hint"))

	f2 := newFakeIDP(t)
	f2.noS256 = true
	_, err = f2.client().AuthCodeURL(context.Background(), req)
	assert.Equal(t, ReasonDiscovery, ReasonOf(err), "RFC 9700 §2.1.1: no S256, no sign-in")
}

func (f *fakeIDP) callback(req AuthRequest) Callback {
	return Callback{Code: "c1", State: req.State, Issuer: f.srv.URL}
}

func TestExchange(t *testing.T) {
	f := newFakeIDP(t)
	c := f.client()
	req, err := NewAuthRequest("", "")
	require.NoError(t, err)
	f.claims = f.goodClaims(req.Nonce)
	tok, err := c.Exchange(context.Background(), f.callback(req), req)
	require.NoError(t, err)
	assert.Equal(t, &IDToken{
		Issuer: f.srv.URL, Subject: "1234567890", Audience: []string{"cid.apps"}, Email: "ana@gmail.com", EmailVerified: true, Name: "Ana",
		IssuedAt: now, ExpiresAt: now.Add(time.Hour), Raw: f.lastID,
	}, tok)
	assert.Equal(t, "cid.apps", f.user)
	assert.Equal(t, "s3cret%2F%2B%3D", f.pass, "RFC 6749 §2.3.1: client_secret_basic, form-encoded")
	assert.Equal(t, req.CodeVerifier, f.form.Get("code_verifier"))
	assert.Equal(t, "https://othra.example/p/acme/federation/google/callback", f.form.Get("redirect_uri"))
	assert.Empty(t, f.form.Get("client_secret"), "never two client auth methods")

	f.claims["iss"] = "idp.example"
	_, err = c.Exchange(context.Background(), f.callback(req), req)
	assert.NoError(t, err, "an accepted second iss form (Google's accounts.google.com)")
	f.claims["email_verified"] = "true"
	f.claims["aud"] = []string{"cid.apps"}
	tok, err = c.Exchange(context.Background(), f.callback(req), req)
	require.NoError(t, err)
	assert.True(t, tok.EmailVerified, "a string email_verified and an array aud are read")
}

func TestExchange_CallbackChecks(t *testing.T) {
	f := newFakeIDP(t)
	c := f.client()
	req, err := NewAuthRequest("", "")
	require.NoError(t, err)
	f.claims = f.goodClaims(req.Nonce)
	for name, tc := range map[string]struct {
		cb     Callback
		reason Reason
	}{
		"another state":                      {Callback{Code: "c1", State: "other", Issuer: f.srv.URL}, ReasonState},
		"no iss though advertised":           {Callback{Code: "c1", State: req.State}, ReasonIssuer},
		"another iss (mix-up)":               {Callback{Code: "c1", State: req.State, Issuer: "https://evil.example"}, ReasonIssuer},
		"Google: a cancel without iss":       {Callback{State: req.State, Error: "access_denied"}, ReasonCancelled},
		"Google: an error without iss":       {Callback{State: req.State, Error: "server_error"}, ReasonError},
		"an error with another iss (mix-up)": {Callback{State: req.State, Issuer: "https://evil.example", Error: "access_denied"}, ReasonIssuer},
		"neither code nor error, and no iss": {Callback{State: req.State}, ReasonIssuer},
		"a code and an error, and no iss":    {Callback{Code: "c1", State: req.State, Error: "access_denied"}, ReasonIssuer},
		"cancelled":                          {Callback{State: req.State, Issuer: f.srv.URL, Error: "access_denied"}, ReasonCancelled},
		"another error":                      {Callback{State: req.State, Issuer: f.srv.URL, Error: "server_error"}, ReasonError},
		"no code":                            {Callback{State: req.State, Issuer: f.srv.URL}, ReasonState},
	} {
		_, err := c.Exchange(context.Background(), tc.cb, req)
		assert.Equal(t, tc.reason, ReasonOf(err), name)
	}
	_, err = c.Exchange(context.Background(), Callback{Code: "c1", State: ""}, AuthRequest{})
	assert.Equal(t, ReasonState, ReasonOf(err), "an empty stored state never matches")

	f.tokenErr = http.StatusBadRequest
	_, err = c.Exchange(context.Background(), f.callback(req), req)
	assert.Equal(t, ReasonTokenExchange, ReasonOf(err))
	f.tokenErr, f.noIDTok = 0, true
	_, err = c.Exchange(context.Background(), f.callback(req), req)
	assert.Equal(t, ReasonTokenExchange, ReasonOf(err), "no id_token")
}

// OIDC Core §3.1.3.7: every claim check fails closed.
func TestExchange_IDTokenChecks(t *testing.T) {
	f := newFakeIDP(t)
	c := f.client()
	req, err := NewAuthRequest("", "")
	require.NoError(t, err)
	for name, tc := range map[string]struct {
		edit   func(cl map[string]any)
		reason Reason
	}{
		"another iss":       {func(cl map[string]any) { cl["iss"] = "https://evil.example" }, ReasonIDToken},
		"another aud":       {func(cl map[string]any) { cl["aud"] = "someone-else" }, ReasonIDToken},
		"an extra aud":      {func(cl map[string]any) { cl["aud"] = []string{"cid.apps", "someone-else"} }, ReasonIDToken},
		"another azp":       {func(cl map[string]any) { cl["azp"] = "someone-else" }, ReasonIDToken},
		"expired":           {func(cl map[string]any) { cl["exp"] = now.Add(-time.Minute).Unix() }, ReasonIDToken},
		"no iat":            {func(cl map[string]any) { delete(cl, "iat") }, ReasonIDToken},
		"iat in the future": {func(cl map[string]any) { cl["iat"] = now.Add(time.Minute).Unix() }, ReasonIDToken},
		"iat too old":       {func(cl map[string]any) { cl["iat"] = now.Add(-time.Hour).Unix() }, ReasonIDToken},
		"another nonce":     {func(cl map[string]any) { cl["nonce"] = "other" }, ReasonNonce},
		"no nonce":          {func(cl map[string]any) { delete(cl, "nonce") }, ReasonNonce},
		"no sub":            {func(cl map[string]any) { delete(cl, "sub") }, ReasonIDToken},
		"a sub over 255":    {func(cl map[string]any) { cl["sub"] = strings.Repeat("x", 256) }, ReasonIDToken},
	} {
		f.claims = f.goodClaims(req.Nonce)
		tc.edit(f.claims)
		_, err := c.Exchange(context.Background(), f.callback(req), req)
		assert.Equal(t, tc.reason, ReasonOf(err), name)
	}

	f.claims = f.goodClaims(req.Nonce)
	f.alg = jose.HS256
	_, err = c.Exchange(context.Background(), f.callback(req), req)
	assert.Equal(t, ReasonIDToken, ReasonOf(err), "HS256 is never accepted")
	f.alg = jose.RS256
	parts := strings.Split(f.sign(), ".")
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"k1"}`)) + "." + parts[1] + "."
	_, err = c.verify(context.Background(), &Metadata{}, none, req.Nonce)
	assert.Equal(t, ReasonIDToken, ReasonOf(err), "alg none is never accepted")
}

// OIDC Core §10.1.1: a rotated key is fetched once on an unknown kid, and an unknown kid can't make Othra hammer the JWKS.
func TestExchange_KeyRotation(t *testing.T) {
	f := newFakeIDP(t)
	c := f.client()
	req, err := NewAuthRequest("", "")
	require.NoError(t, err)
	f.claims = f.goodClaims(req.Nonce)
	_, err = c.Exchange(context.Background(), f.callback(req), req)
	require.NoError(t, err)
	assert.Equal(t, 1, f.jwksHits)

	f.mu.Lock()
	f.kid = "k2"
	f.mu.Unlock()
	f.header = map[jose.HeaderKey]any{"kid": "k2"}
	_, err = c.Exchange(context.Background(), f.callback(req), req)
	require.NoError(t, err, "a rotated kid is refetched")
	assert.Equal(t, 2, f.jwksHits)

	f.header = map[jose.HeaderKey]any{"kid": "k9"}
	_, err = c.Exchange(context.Background(), f.callback(req), req)
	assert.Equal(t, ReasonIDToken, ReasonOf(err))
	assert.Equal(t, 2, f.jwksHits, "no refetch within 30 s of the last one")
}

func TestDiscoveryChecks(t *testing.T) {
	f := newFakeIDP(t)
	f.iss = "https://another.example"
	_, err := f.client().AuthCodeURL(context.Background(), AuthRequest{})
	assert.Equal(t, ReasonMisconfigured, ReasonOf(err), "OIDC Discovery §4.3: the document names another issuer, the deployer's to fix")

	_, err = New(Config{Issuer: "http://127.0.0.1:1"}).AuthCodeURL(context.Background(), AuthRequest{})
	assert.Equal(t, ReasonDiscovery, ReasonOf(err), "unreachable")
	assert.True(t, sameScheme("https://a", "https://a/x"))
	assert.False(t, sameScheme("https://a", "http://a/x"), "no downgrade from an https issuer")
	assert.False(t, sameScheme("https://a", "https://"))
}

func TestExchange_Timeout(t *testing.T) {
	f := newFakeIDP(t)
	c := f.client()
	req, err := NewAuthRequest("", "")
	require.NoError(t, err)
	f.claims = f.goodClaims(req.Nonce)
	_, err = c.AuthCodeURL(context.Background(), req)
	require.NoError(t, err)
	f.slow = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = c.Exchange(ctx, f.callback(req), req)
	assert.Equal(t, ReasonTimeout, ReasonOf(err))
}

func TestParseCallback(t *testing.T) {
	cb := ParseCallback(url.Values{"code": {"c"}, "state": {"s"}, "iss": {"i"}, "error": {"e"}, "error_description": {"d"}})
	assert.Equal(t, Callback{Code: "c", State: "s", Issuer: "i", Error: "e", ErrorDescription: "d"}, cb)
}

func (f *fakeIDP) hits() (meta, jwks int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.metaHits, f.jwksHits
}

func (f *fakeIDP) set(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

func TestTTLPolicy(t *testing.T) {
	p := ttlPolicy{floor: time.Minute, ceiling: time.Hour, fallback: 15 * time.Minute}
	for header, want := range map[string]time.Duration{
		"":                               15 * time.Minute,
		"public, max-age=1800":           30 * time.Minute,
		"max-age=5":                      time.Minute,
		"max-age=86400, must-revalidate": time.Hour,
		"no-store":                       time.Minute,
		"no-cache, max-age=600":          time.Minute,
		"max-age=soon":                   15 * time.Minute,
	} {
		assert.Equal(t, want, p.of(http.Header{"Cache-Control": {header}}), header)
	}
}

// a failed refetch keeps serving the last good JWKS and discovery, and waits before trying again.
func TestCache_ServesStaleAndBacksOff(t *testing.T) {
	f := newFakeIDP(t)
	clock := now
	c := f.client().WithClock(func() time.Time { return clock })
	signIn := func() error {
		req, err := NewAuthRequest("", "")
		require.NoError(t, err)
		f.set(func() {
			f.claims = f.goodClaims(req.Nonce)
			f.claims["iat"], f.claims["exp"] = clock.Unix(), clock.Add(time.Hour).Unix()
		})
		_, err = c.Exchange(context.Background(), f.callback(req), req)
		return err
	}
	require.NoError(t, signIn())
	meta, jwks := f.hits()
	require.Equal(t, 1, meta)
	require.Equal(t, 1, jwks)

	clock = clock.Add(25 * time.Hour)
	f.iss = "https://broken.example"
	f.set(func() { f.jwksCode = http.StatusServiceUnavailable })
	require.NoError(t, signIn(), "an upstream outage after the TTL still verifies with the last good copies")
	meta, jwks = f.hits()
	assert.Equal(t, 2, meta)
	assert.Equal(t, 2, jwks)
	require.NoError(t, signIn())
	meta, jwks = f.hits()
	assert.Equal(t, 2, meta, "backing off: no fetch per sign-in during the outage")
	assert.Equal(t, 2, jwks)

	clock = clock.Add(retryAfterFailure)
	f.iss = ""
	f.set(func() { f.jwksCode = 0 })
	require.NoError(t, signIn())
	meta, jwks = f.hits()
	assert.Equal(t, 3, meta, "after the back-off it tries again")
	assert.Equal(t, 3, jwks)
}

// Cache-Control max-age sets the discovery TTL.
func TestCache_HonoursMaxAge(t *testing.T) {
	f := newFakeIDP(t)
	f.maxAge = "public, max-age=600"
	clock := now
	c := f.client().WithClock(func() time.Time { return clock })
	_, err := c.AuthCodeURL(context.Background(), AuthRequest{})
	require.NoError(t, err)
	clock = clock.Add(11 * time.Minute)
	_, err = c.AuthCodeURL(context.Background(), AuthRequest{})
	require.NoError(t, err)
	meta, _ := f.hits()
	assert.Equal(t, 2, meta, "refetched after max-age, not after the 24 h fallback")
}

// a slow JWKS fetch neither blocks discovery readers nor runs once per caller.
func TestCache_FetchesOutsideTheLock(t *testing.T) {
	f := newFakeIDP(t)
	c := f.client()
	_, err := c.AuthCodeURL(context.Background(), AuthRequest{})
	require.NoError(t, err)
	gate := make(chan struct{})
	f.set(func() { f.jwksGate = gate })
	var wg sync.WaitGroup
	for range 5 {
		wg.Go(func() {
			_, _ = c.src.Key(context.Background(), "k1")
		})
	}
	require.Eventually(t, func() bool { _, jwks := f.hits(); return jwks == 1 }, 5*time.Second, 5*time.Millisecond)
	done := make(chan error, 1)
	go func() {
		_, err := c.AuthCodeURL(context.Background(), AuthRequest{})
		done <- err
	}()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("a JWKS fetch in flight blocked a discovery read")
	}
	close(gate)
	wg.Wait()
	_, jwks := f.hits()
	assert.Equal(t, 1, jwks, "five concurrent misses share one fetch")
}

// OIDC Core §3.1.3.7 step 7: only the algs the upstream IdP advertises, and a JWK's alg must be the token's.
func TestExchange_AlgPinning(t *testing.T) {
	f := newFakeIDP(t)
	c := f.client()
	req, err := NewAuthRequest("", "")
	require.NoError(t, err)
	f.claims = f.goodClaims(req.Nonce)
	f.algs = []string{"ES256"}
	_, err = c.Exchange(context.Background(), f.callback(req), req)
	assert.Equal(t, ReasonIDToken, ReasonOf(err), "an RS256 token from an upstream IdP that advertises only ES256")

	f2 := newFakeIDP(t)
	f2.keyAlg = "RS512"
	c2 := f2.client()
	f2.claims = f2.goodClaims(req.Nonce)
	_, err = c2.Exchange(context.Background(), f2.callback(req), req)
	assert.Equal(t, ReasonIDToken, ReasonOf(err), "a JWK published for RS512 never verifies an RS256 token")

	assert.Equal(t, []jose.SignatureAlgorithm{jose.RS256}, signingAlgs(&Metadata{}), "RS256 when the upstream IdP names none")
	assert.Equal(t, []jose.SignatureAlgorithm{jose.RS256}, signingAlgs(&Metadata{IDTokenSigningAlgValues: []string{"RS256", "HS256", "none"}}))
}

// only a registered error code reaches a log line.
func TestExchange_ErrorIsAllowListed(t *testing.T) {
	f := newFakeIDP(t)
	c := f.client()
	req, err := NewAuthRequest("", "")
	require.NoError(t, err)
	_, err = c.Exchange(context.Background(), Callback{State: req.State, Issuer: f.srv.URL, Error: "temporarily_unavailable"}, req)
	assert.Contains(t, err.Error(), "temporarily_unavailable")
	_, err = c.Exchange(context.Background(), Callback{State: req.State, Issuer: f.srv.URL, Error: strings.Repeat("<x>", 1000)}, req)
	assert.Equal(t, ReasonError, ReasonOf(err))
	assert.NotContains(t, err.Error(), "<x>")
	assert.Contains(t, err.Error(), "other")
}

// Google's two iss forms are accepted for its exact configuration; a downgraded scheme or a longer host is not.
func TestVerify_GoogleIssuerForms(t *testing.T) {
	f := newFakeIDP(t)
	c := New(Config{Issuer: "https://accounts.google.com", ClientID: "cid.apps", AcceptIssuers: []string{"accounts.google.com"}}).
		WithClock(func() time.Time { return now })
	c.src.keys.val = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}}
	c.src.keys.expires = now.Add(time.Hour)
	meta := &Metadata{IDTokenSigningAlgValues: []string{"RS256"}}
	for iss, ok := range map[string]bool{
		"https://accounts.google.com":      true,
		"accounts.google.com":              true,
		"http://accounts.google.com":       false,
		"accounts.google.com.evil":         false,
		"https://accounts.google.com.evil": false,
		"https://accounts.google.com/":     false,
	} {
		f.claims = f.goodClaims("n-1")
		f.claims["iss"] = iss
		tok, err := c.verify(context.Background(), meta, f.sign(), "n-1")
		if !ok {
			assert.Equal(t, ReasonIDToken, ReasonOf(err), iss)
			continue
		}
		require.NoError(t, err, iss)
		assert.Equal(t, "1234567890", tok.Subject, iss)
	}
}
