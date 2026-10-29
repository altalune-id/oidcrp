package oidcrp

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExchange_SessionClaims(t *testing.T) {
	f := newFakeIDP(t)
	req, err := NewAuthRequest("", "")
	require.NoError(t, err)
	f.claims = f.goodClaims(req.Nonce)
	f.claims["auth_time"] = now.Add(-time.Minute).Unix()
	f.claims["sid"] = "Q7mZp2LkV9xRt4NbW8cYd"
	tok, err := f.client().Exchange(context.Background(), f.callback(req), req)
	require.NoError(t, err)
	assert.Equal(t, now.Add(-time.Minute), tok.AuthTime, "OIDC Core §2: auth_time, for max_age and step-up")
	assert.Equal(t, "Q7mZp2LkV9xRt4NbW8cYd", tok.SessionID, "the session the RP-initiated logout ends")
	assert.Equal(t, f.lastID, tok.Raw, "the compact token, for id_token_hint")
}

func TestExchange_TokenType(t *testing.T) {
	f := newFakeIDP(t)
	req, err := NewAuthRequest("", "")
	require.NoError(t, err)
	f.claims = f.goodClaims(req.Nonce)
	f.tokType = "bearer"
	_, err = f.client().Exchange(context.Background(), f.callback(req), req)
	require.NoError(t, err, "RFC 6749 §5.1: the token type is case-insensitive")
	for _, typ := range []string{"DPoP", "mac", "none"} {
		f.tokType = typ
		_, err = f.client().Exchange(context.Background(), f.callback(req), req)
		assert.Equal(t, ReasonTokenExchange, ReasonOf(err), "RFC 6749 §5.1: token_type %q is not Bearer", typ)
	}
	f.tokType = " "
	_, err = f.client().Exchange(context.Background(), f.callback(req), req)
	assert.Equal(t, ReasonTokenExchange, ReasonOf(err), "token_type is required")
}

func TestExchange_ClientAuthentication(t *testing.T) {
	f := newFakeIDP(t)
	req, err := NewAuthRequest("", "")
	require.NoError(t, err)
	f.claims = f.goodClaims(req.Nonce)

	_, err = f.client().Exchange(context.Background(), f.callback(req), req)
	require.NoError(t, err)
	assert.True(t, f.basic, "a confidential client uses client_secret_basic")
	assert.Equal(t, "cid.apps", f.user)
	assert.Empty(t, f.form.Get("client_id"), "RFC 6749 §2.3.1: not both Basic and a body client_id")

	public := New(Config{
		Issuer: f.srv.URL, ClientID: "cid.apps", RedirectURI: "https://othra.example/p/acme/federation/google/callback",
		AcceptIssuers: []string{"idp.example"},
	}).WithClock(func() time.Time { return now })
	_, err = public.Exchange(context.Background(), f.callback(req), req)
	require.NoError(t, err)
	assert.False(t, f.basic, "a public client sends no Authorization header")
	assert.Equal(t, "cid.apps", f.form.Get("client_id"), "OAuth 2.1 §2.1: a public client names itself in the body")
	assert.Equal(t, req.CodeVerifier, f.form.Get("code_verifier"))
}

func TestExchange_RefusesAccessTokenType(t *testing.T) {
	for _, typ := range []string{"at+jwt", "application/at+JWT"} {
		f := newFakeIDP(t)
		req, err := NewAuthRequest("", "")
		require.NoError(t, err)
		f.claims = f.goodClaims(req.Nonce)
		f.header = map[jose.HeaderKey]any{jose.HeaderType: typ}
		_, err = f.client().Exchange(context.Background(), f.callback(req), req)
		assert.Equal(t, ReasonIDToken, ReasonOf(err), "RFC 9068 §4: typ %q is an access token", typ)
	}
}

func TestClientKeys(t *testing.T) {
	f := newFakeIDP(t)
	c := f.client()
	require.NotNil(t, c.Keys())
	assert.Equal(t, f.srv.URL, c.Keys().Issuer(), "the client shares its one KeySource")
}

func TestIsAccessTokenType(t *testing.T) {
	for typ, want := range map[any]bool{"at+jwt": true, " Application/AT+JWT ": true, "JWT": false, nil: false, 7: false} {
		h := jose.Header{ExtraHeaders: map[jose.HeaderKey]any{}}
		if typ != nil {
			h.ExtraHeaders[jose.HeaderType] = typ
		}
		assert.Equal(t, want, IsAccessTokenType(h), "%v", typ)
	}
}

func TestExchange_OAuthError(t *testing.T) {
	for _, c := range []struct {
		status int
		body   string
		want   string
	}{
		{400, `{"error":"invalid_grant","error_description":"code already used"}`, "invalid_grant"},
		{401, `{"error":"invalid_client"}`, "invalid_client"},
		{400, `{"error":"<script>made up</script>"}`, "other"},
		{400, `not json`, ""},
		{500, `{"error":"server_error"}`, ""},
	} {
		f := newFakeIDP(t)
		req, err := NewAuthRequest("", "")
		require.NoError(t, err)
		f.tokenErr, f.errBody = c.status, c.body
		_, err = f.client().Exchange(context.Background(), f.callback(req), req)
		assert.Equal(t, ReasonTokenExchange, ReasonOf(err), c.body)
		assert.Equal(t, c.want, OAuthErrorOf(err), "RFC 6749 §5.2: %d %s", c.status, c.body)
		assert.NotContains(t, err.Error(), "code already used", "no upstream text in the error")
	}
	assert.Empty(t, OAuthErrorOf(errors.New("plain")))
}

func TestEndSessionURL(t *testing.T) {
	f := newFakeIDP(t)
	f.endSess = f.srv.URL + "/oauth2/end-session?ui=1"
	raw, err := f.client().EndSessionURL(context.Background(), "the.id.token", "https://console.example/signed-out", "st1")
	require.NoError(t, err)
	u, err := url.Parse(raw)
	require.NoError(t, err)
	q := u.Query()
	assert.Equal(t, f.srv.URL+"/oauth2/end-session", u.Scheme+"://"+u.Host+u.Path)
	assert.Equal(t, "1", q.Get("ui"), "the endpoint's own query is kept")
	assert.Equal(t, "the.id.token", q.Get("id_token_hint"))
	assert.Equal(t, "cid.apps", q.Get("client_id"))
	assert.Equal(t, "https://console.example/signed-out", q.Get("post_logout_redirect_uri"))
	assert.Equal(t, "st1", q.Get("state"))

	raw, err = f.client().EndSessionURL(context.Background(), "", "", "")
	require.NoError(t, err)
	q = must(t, raw).Query()
	assert.False(t, q.Has("id_token_hint") || q.Has("post_logout_redirect_uri") || q.Has("state"), "empty values are left out")

	plain := newFakeIDP(t)
	raw, err = plain.client().EndSessionURL(context.Background(), "the.id.token", "", "")
	require.NoError(t, err)
	assert.Empty(t, raw, "an issuer without end_session_endpoint has no RP-initiated logout")

	other := newFakeIDP(t)
	other.endSess = "javascript:alert(1)"
	_, err = other.client().EndSessionURL(context.Background(), "", "", "")
	assert.Equal(t, ReasonDiscovery, ReasonOf(err), "an end_session_endpoint off the issuer's scheme fails discovery")
}

func must(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

func TestKeySource(t *testing.T) {
	f := newFakeIDP(t)
	src := NewKeySource(f.srv.URL, nil).WithClock(func() time.Time { return now })
	assert.Equal(t, f.srv.URL, src.Issuer())
	assert.NotNil(t, src.HTTPClient())
	meta, err := src.Metadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, f.srv.URL+"/jwks", meta.JWKSURI)
	key, err := src.Key(context.Background(), "k1")
	require.NoError(t, err)
	assert.Equal(t, "k1", key.KeyID)
	assert.Equal(t, []jose.SignatureAlgorithm{jose.RS256}, meta.SigningAlgorithms())
	_, err = src.Key(context.Background(), "k2")
	assert.Equal(t, ReasonIDToken, ReasonOf(err), "an unknown kid after one refetch")

	bad := NewKeySource("https://other.example", f.srv.Client())
	bad.issuer = f.srv.URL + "/not-here"
	_, err = bad.Key(context.Background(), "k1")
	assert.Equal(t, ReasonDiscovery, ReasonOf(err), "no discovery, no keys")
}
