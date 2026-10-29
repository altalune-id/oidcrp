package oidcrp

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

type tokenResponse struct {
	AccessToken  string          `json:"access_token"`
	TokenType    string          `json:"token_type"`
	RefreshToken string          `json:"refresh_token"`
	ExpiresIn    json.RawMessage `json:"expires_in"`
	Scope        string          `json:"scope"`
	IDToken      string          `json:"id_token"`
}

// Refresh renews prev (RFC 6749 Section 6); an error with a non-nil set still carries the rotated RefreshToken to store.
func (c *Client) Refresh(ctx context.Context, prev TokenSet) (*TokenSet, error) {
	if prev.RefreshToken == "" {
		return nil, &Error{Reason: ReasonTokenExchange, Err: errors.New("no refresh token")}
	}
	meta, err := c.src.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	out, err := c.grant(ctx, meta, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {prev.RefreshToken}})
	if err != nil {
		return nil, err
	}
	rotated := cmp.Or(out.RefreshToken, prev.RefreshToken)
	// SECURITY: RFC 9700 §4.14.2: the issuer has spent prev's refresh token, so a failed check still hands back the rotated one.
	granted := prev.Scopes
	if len(granted) == 0 {
		granted = c.cfg.Scopes
	}
	set, err := c.tokenSet(out, granted)
	if err != nil {
		return &TokenSet{RefreshToken: rotated}, err
	}
	set.RefreshToken = rotated
	return set, nil
}

// Revoke asks the upstream IdP to revoke token (RFC 7009 Section 2.1); tokenTypeHint is access_token, refresh_token or "".
func (c *Client) Revoke(ctx context.Context, token, tokenTypeHint string) error {
	if token == "" {
		return &Error{Reason: ReasonTokenExchange, Err: errors.New("no token")}
	}
	meta, err := c.src.Metadata(ctx)
	if err != nil {
		return err
	}
	if meta.RevocationEndpoint == "" {
		return &Error{Reason: ReasonDiscovery, Err: errors.New("the upstream IdP has no revocation_endpoint")}
	}
	form := url.Values{"token": {token}}
	if tokenTypeHint != "" {
		form.Set("token_type_hint", tokenTypeHint)
	}
	r, err := c.clientRequest(ctx, meta.RevocationEndpoint, form)
	if err != nil {
		return err
	}
	_, _, err = c.src.do(r, ReasonTokenExchange)
	return err
}

func (c *Client) grant(ctx context.Context, meta *Metadata, form url.Values) (*tokenResponse, error) {
	if c.cfg.Resource != "" {
		form.Set("resource", c.cfg.Resource)
	}
	r, err := c.clientRequest(ctx, meta.TokenEndpoint, form)
	if err != nil {
		return nil, err
	}
	var out tokenResponse
	if _, err := c.src.doJSON(r, ReasonTokenExchange, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) clientRequest(ctx context.Context, endpoint string, form url.Values) (*http.Request, error) {
	if c.cfg.ClientSecret == "" {
		form.Set("client_id", c.cfg.ClientID)
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, &Error{Reason: ReasonTokenExchange, Err: err}
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "application/json")
	if c.cfg.ClientSecret != "" {
		r.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret))
	}
	return r, nil
}

// NOTE: RFC 6749 §5.1: access_token is required, expires_in is a positive integer when present, and scope replaces the requested scopes.
func (c *Client) tokenSet(out *tokenResponse, granted []string) (*TokenSet, error) {
	switch {
	case !isBearer(out.TokenType):
		return nil, &Error{Reason: ReasonTokenExchange, Err: errors.New("the token type is not Bearer")}
	case out.AccessToken == "":
		return nil, &Error{Reason: ReasonTokenExchange, Err: errors.New("the token response has no access_token")}
	}
	set := &TokenSet{AccessToken: out.AccessToken, RefreshToken: out.RefreshToken, Scopes: slices.Clone(granted)}
	if scope := strings.Fields(out.Scope); len(scope) > 0 {
		set.Scopes = scope
	}
	if raw := string(out.ExpiresIn); raw != "" && raw != "null" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n <= 0 || n > int64(math.MaxInt64/time.Second) {
			return nil, &Error{Reason: ReasonTokenExchange, Err: errors.New("expires_in is not a positive integer")}
		}
		set.ExpiresAt = c.now().Add(time.Duration(n) * time.Second)
	}
	return set, nil
}

func isBearer(tokenType string) bool {
	return strings.EqualFold(strings.TrimSpace(tokenType), "Bearer")
}
