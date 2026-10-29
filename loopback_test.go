package oidcrp_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/altalune-id/oidcrp"
	"github.com/altalune-id/oidcrp/oidcrptest"
)

func nativeClient(idp *oidcrptest.IDP, redirect string) *oidcrp.Client {
	return oidcrp.New(oidcrp.Config{
		Issuer: idp.Issuer(), ClientID: "cli", RedirectURI: redirect, Scopes: []string{"openid", "email"}, HTTPClient: idp.Client(),
	})
}

func follow(t *testing.T, authURL string, q url.Values) (int, string) {
	t.Helper()
	u, err := url.Parse(authURL)
	require.NoError(t, err)
	r, err := http.Get(u.Query().Get("redirect_uri") + "?" + q.Encode()) //nolint:noctx // a test client on loopback.
	require.NoError(t, err)
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	return r.StatusCode, string(body)
}

func TestRunLoopback_SignsIn(t *testing.T) {
	idp := oidcrptest.New(t)
	var authURL, page string
	tok, err := nativeClient(idp, "http://127.0.0.1/callback").RunLoopback(t.Context(), oidcrp.LoopbackConfig{
		LoginHint: "ana@gmail.com",
		Open: func(_ context.Context, u string) error {
			authURL = u
			var status int
			status, page = follow(t, u, idp.Authorize(u))
			assert.Equal(t, http.StatusOK, status)
			return nil
		},
	})
	require.NoError(t, err)
	assert.Equal(t, idp.User.Subject, tok.Subject)
	assert.Contains(t, page, "Sign-in received")

	q := mustQuery(t, authURL)
	redirect, err := url.Parse(q.Get("redirect_uri"))
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", redirect.Hostname(), "RFC 8252 §7.3: the registered loopback IP")
	assert.NotEmpty(t, redirect.Port(), "RFC 8252 §7.3: the port is chosen at run time")
	assert.Equal(t, "/callback", redirect.Path)
	assert.Equal(t, "S256", q.Get("code_challenge_method"), "RFC 8252 §8.1: native clients use PKCE")
	assert.Equal(t, "ana@gmail.com", q.Get("login_hint"))
}

func TestRunLoopback_FixedPortAndIPv6(t *testing.T) {
	idp := oidcrptest.New(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())

	var authURL string
	_, err = nativeClient(idp, "http://127.0.0.1/callback").RunLoopback(t.Context(), oidcrp.LoopbackConfig{
		Port: port,
		Open: func(_ context.Context, u string) error {
			authURL = u
			follow(t, u, idp.Authorize(u))
			return nil
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:"+strconv.Itoa(port)+"/callback", mustQuery(t, authURL).Get("redirect_uri"))

	if v6, err := net.Listen("tcp", "[::1]:0"); err == nil {
		require.NoError(t, v6.Close())
		_, err = nativeClient(idp, "http://[::1]/callback").RunLoopback(t.Context(), oidcrp.LoopbackConfig{
			Open: func(_ context.Context, u string) error {
				follow(t, u, idp.Authorize(u))
				return nil
			},
		})
		require.NoError(t, err, "RFC 8252 §7.3: the IPv6 loopback works the same")
	}
}

func TestRunLoopback_IgnoresStrayRequests(t *testing.T) {
	idp := oidcrptest.New(t)
	tok, err := nativeClient(idp, "http://127.0.0.1/callback").RunLoopback(t.Context(), oidcrp.LoopbackConfig{
		Open: func(_ context.Context, u string) error {
			q := idp.Authorize(u)
			forged := url.Values{"code": {"stolen"}, "state": {"guess"}}
			status, body := follow(t, u, forged)
			assert.Equal(t, http.StatusBadRequest, status, "a request without this attempt's state does not end the sign-in")
			assert.NotContains(t, body, "stolen")
			status, _ = follow(t, u, q)
			assert.Equal(t, http.StatusOK, status)
			status, _ = follow(t, u, q)
			assert.Equal(t, http.StatusConflict, status, "only one callback is taken")
			return nil
		},
	})
	require.NoError(t, err)
	assert.Equal(t, idp.User.Subject, tok.Subject)
}

func TestRunLoopback_Denied(t *testing.T) {
	idp := oidcrptest.New(t)
	_, err := nativeClient(idp, "http://127.0.0.1/callback").RunLoopback(t.Context(), oidcrp.LoopbackConfig{
		Open: func(_ context.Context, u string) error {
			q := idp.Deny(u)
			q.Set("error_description", "<script>evil</script>")
			_, page := follow(t, u, q)
			assert.Contains(t, page, "access_denied")
			assert.NotContains(t, page, "evil", "the page never echoes error_description")
			return nil
		},
	})
	assert.Equal(t, oidcrp.ReasonCancelled, oidcrp.ReasonOf(err))
}

func TestRunLoopback_StopsOnContext(t *testing.T) {
	idp := oidcrptest.New(t)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, err := nativeClient(idp, "http://127.0.0.1/callback").RunLoopback(ctx, oidcrp.LoopbackConfig{
		Open: func(context.Context, string) error { return nil },
	})
	assert.Equal(t, oidcrp.ReasonTimeout, oidcrp.ReasonOf(err))
}

func TestRunLoopback_OpenError(t *testing.T) {
	idp := oidcrptest.New(t)
	boom := errors.New("no terminal")
	_, err := nativeClient(idp, "http://127.0.0.1/callback").RunLoopback(t.Context(), oidcrp.LoopbackConfig{
		Open: func(context.Context, string) error { return boom },
	})
	assert.ErrorIs(t, err, boom)
}

func TestRunLoopback_RefusesBadConfig(t *testing.T) {
	idp := oidcrptest.New(t)
	for _, redirect := range []string{
		"http://localhost/callback",
		"https://127.0.0.1/callback",
		"http://127.0.0.1:8080/callback",
		"http://192.168.1.10/callback",
		"http://127.0.0.1/callback?x=1",
		"https://app.example/callback",
		"::not a url",
	} {
		_, err := nativeClient(idp, redirect).RunLoopback(t.Context(), oidcrp.LoopbackConfig{
			Open: func(context.Context, string) error { return nil },
		})
		assert.Equal(t, oidcrp.ReasonMisconfigured, oidcrp.ReasonOf(err), "RFC 8252 §7.3, §8.3: %s", redirect)
	}
	_, err := nativeClient(idp, "http://127.0.0.1/callback").RunLoopback(t.Context(), oidcrp.LoopbackConfig{})
	assert.Equal(t, oidcrp.ReasonMisconfigured, oidcrp.ReasonOf(err), "Open is required")
}

func TestRunLoopback_PortInUse(t *testing.T) {
	idp := oidcrptest.New(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	_, err = nativeClient(idp, "http://127.0.0.1/callback").RunLoopback(t.Context(), oidcrp.LoopbackConfig{
		Port: ln.Addr().(*net.TCPAddr).Port,
		Open: func(context.Context, string) error { return nil },
	})
	assert.Equal(t, oidcrp.ReasonMisconfigured, oidcrp.ReasonOf(err))
}

func TestOpenBrowser_RefusesNonHTTP(t *testing.T) {
	for _, raw := range []string{"file:///etc/passwd", "javascript:alert(1)", "/relative", "https://"} {
		err := oidcrp.OpenBrowser(t.Context(), raw)
		require.Error(t, err, raw)
		assert.True(t, strings.Contains(err.Error(), "http or https"), raw)
	}
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u.Query()
}
