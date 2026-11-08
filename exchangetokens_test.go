package oidcrp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExchangeTokens(t *testing.T) {
	f := newFakeIDP(t)
	req, err := NewAuthRequest("", "")
	require.NoError(t, err)
	f.claims = f.goodClaims(req.Nonce)
	f.extra = map[string]any{"expires_in": 3600, "scope": "openid email"}
	set, err := f.resourceClient().ExchangeTokens(t.Context(), f.callback(req), req)
	require.NoError(t, err)
	assert.Equal(t, &TokenSet{
		IDToken: &IDToken{
			Issuer: f.srv.URL, Subject: "1234567890", Audience: []string{"cid.apps"}, Email: "ana@gmail.com", EmailVerified: true, Name: "Ana",
			IssuedAt: now, ExpiresAt: now.Add(time.Hour), Raw: f.lastID,
		},
		AccessToken: "upstream-at", RefreshToken: "upstream-rt", ExpiresAt: now.Add(time.Hour), Scopes: []string{"openid", "email"},
	}, set, "RFC 6749 §5.1 and OIDC Core §3.1.3.7: the tokens and the verified ID token")
	assert.Equal(t, "https://notes.example/mcp", f.form.Get("resource"), "RFC 8707 §2.2")
	assert.Equal(t, req.CodeVerifier, f.form.Get("code_verifier"), "RFC 7636 §4.5")
	assert.Equal(t, "authorization_code", f.form.Get("grant_type"), "RFC 6749 §4.1.3")

	f.extra = nil
	set, err = f.client().ExchangeTokens(t.Context(), f.callback(req), req)
	require.NoError(t, err)
	assert.Equal(t, []string{"openid", "email", "profile"}, set.Scopes, "RFC 6749 §5.1: no scope means granted as requested")
	assert.True(t, set.ExpiresAt.IsZero())
}

func TestExchangeTokens_Checks(t *testing.T) {
	for name, tc := range map[string]struct {
		tweak  func(*fakeIDP, *AuthRequest, *Callback)
		reason Reason
	}{
		"RFC 6749 §10.12: another state":          {func(_ *fakeIDP, _ *AuthRequest, cb *Callback) { cb.State = "other" }, ReasonState},
		"RFC 9207 §2.4: another iss":              {func(_ *fakeIDP, _ *AuthRequest, cb *Callback) { cb.Issuer = "https://evil.example" }, ReasonIssuer},
		"RFC 6749 §4.1.2.1: access_denied":        {func(_ *fakeIDP, _ *AuthRequest, cb *Callback) { cb.Code, cb.Error = "", "access_denied" }, ReasonCancelled},
		"RFC 6749 §5.1: no access_token":          {func(f *fakeIDP, _ *AuthRequest, _ *Callback) { f.extra = map[string]any{"access_token": nil} }, ReasonTokenExchange},
		"RFC 6750 §4: not Bearer":                 {func(f *fakeIDP, _ *AuthRequest, _ *Callback) { f.tokType = "mac" }, ReasonTokenExchange},
		"OIDC Core §3.1.3.3: openid, no id_token": {func(f *fakeIDP, _ *AuthRequest, _ *Callback) { f.noIDTok = true }, ReasonTokenExchange},
		"OIDC Core §3.1.3.7: another nonce":       {func(_ *fakeIDP, req *AuthRequest, _ *Callback) { req.Nonce = "other" }, ReasonNonce},
		"OIDC Core §3.1.3.7: another audience":    {func(f *fakeIDP, _ *AuthRequest, _ *Callback) { f.claims["aud"] = "someone-else" }, ReasonIDToken},
		"RFC 6749 §5.2: invalid_grant":            {func(f *fakeIDP, _ *AuthRequest, _ *Callback) { f.tokenErr = 400 }, ReasonTokenExchange},
	} {
		f := newFakeIDP(t)
		req, err := NewAuthRequest("", "")
		require.NoError(t, err)
		f.claims = f.goodClaims(req.Nonce)
		cb := f.callback(req)
		tc.tweak(f, &req, &cb)
		set, err := f.client().ExchangeTokens(t.Context(), cb, req)
		assert.Nil(t, set, name)
		assert.Equal(t, tc.reason, ReasonOf(err), name)
	}
}

func TestExchangeTokens_WithoutOpenIDReadsNoIDToken(t *testing.T) {
	f := newFakeIDP(t)
	c := f.client()
	c.cfg.Scopes = []string{"mcp:tools"}
	req, err := NewAuthRequest("", "")
	require.NoError(t, err)
	f.claims = map[string]any{"sub": "forged"}
	set, err := c.ExchangeTokens(t.Context(), f.callback(req), req)
	require.NoError(t, err, "RFC 6749 §5.1: a plain OAuth grant has no ID token to verify")
	assert.Nil(t, set.IDToken, "an id_token nobody asked for is not trusted")
	assert.Equal(t, "upstream-at", set.AccessToken)
	_, jwks := f.hits()
	assert.Zero(t, jwks, "no key lookup for an unrequested ID token")
	assert.False(t, f.form.Has("scope"), "RFC 6749 §4.1.3: the code request carries no scope")
}
