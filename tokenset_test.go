package oidcrp_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/altalune-id/oidcrp"
	"github.com/altalune-id/oidcrp/oidcrptest"
)

const resource = "https://notes.example/mcp"

func signIn(t *testing.T, idp *oidcrptest.IDP) (*oidcrp.Client, *oidcrp.TokenSet) {
	t.Helper()
	c := oidcrp.New(oidcrp.Config{
		Issuer: idp.Issuer(), ClientID: "cli", RedirectURI: "http://127.0.0.1/callback", Scopes: []string{"openid", "email"},
		HTTPClient: idp.Client(), Resource: resource,
	})
	var authURL string
	set, err := c.RunLoopback(t.Context(), oidcrp.LoopbackConfig{
		Open: func(_ context.Context, u string) error {
			authURL = u
			follow(t, u, idp.Authorize(u))
			return nil
		},
	})
	require.NoError(t, err)
	assert.Equal(t, resource, mustQuery(t, authURL).Get("resource"), "RFC 8707 §2.1: resource on the authorization request")
	return c, set
}

func accessClaims(t *testing.T, raw string) (string, map[string]any) {
	t.Helper()
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &claims))
	typ, _ := jws.Signatures[0].Header.ExtraHeaders[jose.HeaderType].(string)
	return typ, claims
}

func TestRunLoopback_ReturnsTokenSet(t *testing.T) {
	idp := oidcrptest.New(t)
	before := time.Now()
	_, set := signIn(t, idp)

	require.NotNil(t, set.IDToken, "OIDC Core §3.1.3.7: the verified ID token of the sign-in")
	assert.Equal(t, idp.User.Subject, set.IDToken.Subject)
	assert.NotEmpty(t, set.RefreshToken, "RFC 6749 §5.1: refresh_token")
	assert.WithinDuration(t, before.Add(15*time.Minute), set.ExpiresAt, 5*time.Second, "RFC 6749 §5.1: ExpiresAt from expires_in")
	assert.Equal(t, []string{"openid", "email"}, set.Scopes, "RFC 6749 §5.1: the granted scope")
	typ, claims := accessClaims(t, set.AccessToken)
	assert.Equal(t, "at+jwt", typ, "RFC 9068 §2.1")
	assert.Equal(t, resource, claims["aud"], "RFC 8707 §2: the access token's audience is the requested resource")
	assert.Equal(t, oidcrptest.Resources{Authorize: resource, Code: resource}, idp.Resources(), "RFC 8707 §2.2: resource on the code request")
}

func TestRefresh_RotatesWithTheTestIDP(t *testing.T) {
	idp := oidcrptest.New(t)
	c, set := signIn(t, idp)

	next, err := c.Refresh(t.Context(), *set)
	require.NoError(t, err)
	assert.Nil(t, next.IDToken, "OIDC Core §12.2: a refresh's ID token is not used")
	assert.NotEmpty(t, next.AccessToken)
	assert.NotEqual(t, set.RefreshToken, next.RefreshToken, "RFC 9700 §4.14.2: the refresh token rotates")
	assert.Equal(t, resource, idp.Resources().Refresh, "RFC 8707 §2.2: resource on the refresh request")
	_, claims := accessClaims(t, next.AccessToken)
	assert.Equal(t, resource, claims["aud"])

	_, err = c.Refresh(t.Context(), *set)
	assert.Equal(t, oidcrp.ReasonTokenExchange, oidcrp.ReasonOf(err))
	assert.Equal(t, "invalid_grant", oidcrp.OAuthErrorOf(err), "RFC 6749 §5.2: a reused refresh token is invalid_grant")

	_, err = c.Refresh(t.Context(), oidcrp.TokenSet{})
	assert.Equal(t, oidcrp.ReasonTokenExchange, oidcrp.ReasonOf(err))
}

func TestRevoke_WithTheTestIDP(t *testing.T) {
	idp := oidcrptest.New(t)
	c, set := signIn(t, idp)

	require.NoError(t, c.Revoke(t.Context(), set.RefreshToken, "refresh_token"))
	require.NoError(t, c.Revoke(t.Context(), "unknown", ""), "RFC 7009 §2.2: an unknown token is still 200")
	assert.Equal(t, 2, idp.Revocations())
	_, err := c.Refresh(t.Context(), *set)
	assert.Equal(t, "invalid_grant", oidcrp.OAuthErrorOf(err), "RFC 7009 §2.1: a revoked refresh token is refused")
}
