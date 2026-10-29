# oidcrp

A small OpenID Connect relying party for Go: discovery, JWKS, the authorization code flow with PKCE, state and nonce, ID token verification and end-session.

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

`oidcrptest` starts an in-memory OpenID provider for tests. See `example_test.go`.

Dependencies: the standard library and go-jose. Licensed under Apache-2.0 (see `LICENSE` and `NOTICE`).
