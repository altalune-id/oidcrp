package oidcrp_test

import (
	"context"
	"fmt"

	"github.com/altalune-id/oidcrp"
	"github.com/altalune-id/oidcrp/oidcrptest"
)

func ExampleClient_Exchange() {
	idp := oidcrptest.Start()
	defer idp.Close()

	c := oidcrp.New(oidcrp.Config{
		Issuer: idp.Issuer(), ClientID: "notes", ClientSecret: "s3cret", RedirectURI: "https://notes.example/callback",
		Scopes: []string{"openid", "email"}, HTTPClient: idp.Client(),
	})
	ctx := context.Background()
	req, err := oidcrp.NewAuthRequest("", "")
	if err != nil {
		panic(err)
	}
	authURL, err := c.AuthCodeURL(ctx, req)
	if err != nil {
		panic(err)
	}
	callback := idp.Authorize(authURL)
	tok, err := c.Exchange(ctx, oidcrp.ParseCallback(callback), req)
	if err != nil {
		panic(err)
	}
	fmt.Println(tok.Subject, tok.Email)
	// Output: 110169484474386276334 ana@gmail.com
}
