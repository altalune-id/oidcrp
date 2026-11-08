# oidcrp

A small OpenID Connect relying party for Go: discovery, JWKS, the authorization code flow with PKCE, state and nonce, ID token verification, refresh, revocation and end-session.

```sh
go get github.com/altalune-id/oidcrp
```

```go
c := oidcrp.New(oidcrp.Config{
	Issuer:       "https://auth.example/p/acme",
	ClientID:     "notes",
	ClientSecret: secret,
	RedirectURI:  "https://notes.example/callback",
	Scopes:       []string{"openid", "email", "profile"},
})
req, _ := oidcrp.NewAuthRequest("", "") // keep req (state, nonce, PKCE verifier) until the callback
authURL, _ := c.AuthCodeURL(ctx, req)
// ...redirect the browser to authURL, then on the callback:
tok, err := c.Exchange(ctx, oidcrp.ParseCallback(r.URL.Query()), req)
```

For a CLI, `RunLoopback` signs a native client in through a loopback redirect (RFC 8252): register `http://127.0.0.1/callback` and it picks the port at run time. `OpenBrowser` opens the authorization URL.
It returns a `TokenSet`; `Refresh` renews it (RFC 6749 Section 6) and `Revoke` revokes a token (RFC 7009). Set `Config.Resource` to send an RFC 8707 resource indicator.

For an OAuth client that keeps the upstream tokens, `ExchangeTokens` returns the `TokenSet` from the callback; its `IDToken` is verified when `openid` is requested and nil otherwise. Set `Config.OAuthMetadata` to read RFC 8414 authorization server metadata first, then OIDC discovery when the server publishes none.

`oidcrptest` starts an in-memory OpenID provider for tests. See `example_test.go`.

Dependencies: the standard library, golang.org/x/sync and go-jose. Licensed under Apache-2.0 (see `LICENSE` and `NOTICE`).
