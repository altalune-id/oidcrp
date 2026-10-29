package oidcrp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (f *fakeIDP) publicClient() *Client {
	return New(Config{
		Issuer: f.srv.URL, ClientID: "cid.apps", RedirectURI: "http://127.0.0.1/callback", Scopes: []string{"openid", "email"},
		Resource: "https://notes.example/mcp",
	}).WithClock(func() time.Time { return now })
}

func (f *fakeIDP) resourceClient() *Client {
	c := f.client()
	c.cfg.Resource = "https://notes.example/mcp"
	return c
}

func TestRefresh_Request(t *testing.T) {
	f := newFakeIDP(t)
	f.extra = map[string]any{"id_token": "not.a.jwt", "expires_in": 3600, "scope": "openid"}
	set, err := f.resourceClient().Refresh(t.Context(), TokenSet{RefreshToken: "rt-1"})
	require.NoError(t, err)
	assert.Equal(t, "refresh_token", f.form.Get("grant_type"), "RFC 6749 §6")
	assert.Equal(t, "rt-1", f.form.Get("refresh_token"))
	assert.Equal(t, "https://notes.example/mcp", f.form.Get("resource"), "RFC 8707 §2.2")
	assert.False(t, f.form.Has("scope"), "RFC 6749 §6: no scope keeps the grant's scope")
	assert.False(t, f.form.Has("redirect_uri"))
	assert.True(t, f.basic, "RFC 6749 §6: a confidential client authenticates")
	assert.False(t, f.form.Has("client_id"), "RFC 6749 §2.3.1: not both Basic and a body client_id")
	assert.Equal(t, &TokenSet{
		AccessToken: "upstream-at", RefreshToken: "upstream-rt", ExpiresAt: now.Add(time.Hour), Scopes: []string{"openid"},
	}, set, "OIDC Core §12.2: the refresh's id_token is ignored; RFC 6749 §5.1: scope replaces the requested scopes")

	f.extra = map[string]any{"refresh_token": nil}
	set, err = f.publicClient().Refresh(t.Context(), TokenSet{RefreshToken: "rt-1"})
	require.NoError(t, err)
	assert.False(t, f.basic, "a public client sends no Authorization header")
	assert.Equal(t, "cid.apps", f.form.Get("client_id"), "OAuth 2.1 §2.1: a public client names itself in the body")
	assert.Equal(t, "rt-1", set.RefreshToken, "RFC 6749 §6: no new refresh token keeps the presented one")
	assert.True(t, set.ExpiresAt.IsZero(), "RFC 6749 §5.1: expires_in is RECOMMENDED, not required")
	assert.Equal(t, []string{"openid", "email"}, set.Scopes, "RFC 6749 §5.1: no scope means the requested scopes")

	_, err = f.client().Refresh(t.Context(), TokenSet{RefreshToken: "rt-1"})
	require.NoError(t, err)
	assert.False(t, f.form.Has("resource"), "RFC 8707 §2: no Resource, no resource parameter")

	f.extra = nil
	set, err = f.client().Refresh(t.Context(), TokenSet{RefreshToken: "rt-1", Scopes: []string{"openid"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"openid"}, set.Scopes, "RFC 6749 §6: no scope in the answer keeps the granted scope")

	_, err = f.client().Refresh(t.Context(), TokenSet{})
	assert.Equal(t, ReasonTokenExchange, ReasonOf(err), "no refresh token, no request")
}

func TestRefresh_ResponseChecks(t *testing.T) {
	for name, extra := range map[string]map[string]any{
		"zero expires_in":     {"expires_in": 0},
		"negative expires_in": {"expires_in": -1},
		"string expires_in":   {"expires_in": "3600"},
		"fraction expires_in": {"expires_in": 1.5},
		"huge expires_in":     {"expires_in": 1e30},
		"no access_token":     {"access_token": nil},
		"not Bearer":          {"token_type": "mac"},
	} {
		f := newFakeIDP(t)
		f.extra = extra
		set, err := f.client().Refresh(t.Context(), TokenSet{RefreshToken: "rt-1"})
		assert.Equal(t, ReasonTokenExchange, ReasonOf(err), "RFC 6749 §5.1: %s", name)
		require.NotNil(t, set, name)
		assert.Equal(t, TokenSet{RefreshToken: "upstream-rt"}, *set, "RFC 9700 §4.14.2: the rotated refresh token survives a failed check: %s", name)
	}

	f := newFakeIDP(t)
	f.tokenErr = 400
	_, err := f.client().Refresh(t.Context(), TokenSet{RefreshToken: "rt-1"})
	assert.Equal(t, ReasonTokenExchange, ReasonOf(err))
	assert.Equal(t, "invalid_grant", OAuthErrorOf(err), "RFC 6749 §5.2: invalid_grant means sign in again")
}

func TestExchange_ResourceAndLenientTokens(t *testing.T) {
	f := newFakeIDP(t)
	req, err := NewAuthRequest("", "")
	require.NoError(t, err)
	f.claims = f.goodClaims(req.Nonce)
	f.extra = map[string]any{"access_token": nil, "expires_in": "3600"}
	_, err = f.resourceClient().Exchange(t.Context(), f.callback(req), req)
	require.NoError(t, err, "Exchange needs only the ID token")
	assert.Equal(t, "https://notes.example/mcp", f.form.Get("resource"), "RFC 8707 §2.2: resource on the code request")

	raw, err := f.resourceClient().AuthCodeURL(t.Context(), req)
	require.NoError(t, err)
	assert.Contains(t, raw, "resource=https%3A%2F%2Fnotes.example%2Fmcp", "RFC 8707 §2.1")
}

func TestRevoke(t *testing.T) {
	f := newFakeIDP(t)
	f.revoke = true
	require.NoError(t, f.client().Revoke(t.Context(), "rt-1", "refresh_token"), "RFC 7009 §2.2: 200 is success")
	assert.Equal(t, "rt-1", f.form.Get("token"), "RFC 7009 §2.1")
	assert.Equal(t, "refresh_token", f.form.Get("token_type_hint"))
	assert.True(t, f.basic, "RFC 7009 §2.1: a confidential client authenticates")
	assert.Equal(t, "s3cret%2F%2B%3D", f.pass)
	assert.False(t, f.form.Has("client_id"))
	assert.False(t, f.form.Has("resource"))

	require.NoError(t, f.publicClient().Revoke(t.Context(), "unknown", ""), "RFC 7009 §2.2: an unknown token is still 200")
	assert.False(t, f.basic)
	assert.Equal(t, "cid.apps", f.form.Get("client_id"), "RFC 7009 §2.1: a public client names itself")
	assert.False(t, f.form.Has("token_type_hint"))

	err := f.client().Revoke(t.Context(), "", "")
	assert.Equal(t, ReasonTokenExchange, ReasonOf(err), "no token, no request")

	f.revCode = 503
	err = f.client().Revoke(t.Context(), "rt-1", "")
	assert.Equal(t, ReasonTokenExchange, ReasonOf(err), "RFC 7009 §2.2.1: 503 means retry later")
	assert.Empty(t, OAuthErrorOf(err))

	f.revCode, f.errBody = 400, `{"error":"unsupported_token_type"}`
	err = f.client().Revoke(t.Context(), "rt-1", "access_token")
	assert.Equal(t, ReasonTokenExchange, ReasonOf(err))
	assert.Equal(t, "unsupported_token_type", OAuthErrorOf(err), "RFC 7009 §2.2.1")

	err = newFakeIDP(t).client().Revoke(t.Context(), "rt-1", "")
	assert.Equal(t, ReasonDiscovery, ReasonOf(err), "RFC 7009 §2: no revocation_endpoint, nothing to call")
}
