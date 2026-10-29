package oidcrp

import (
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

// Refresh redeems refreshToken for a new access token (RFC 6749 Section 6); an invalid_grant OAuthErrorOf means sign in again.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*TokenSet, error) {
	if refreshToken == "" {
		return nil, &Error{Reason: ReasonTokenExchange, Err: errors.New("no refresh token")}
	}
	meta, err := c.src.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	out, err := c.grant(ctx, meta, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
	if err != nil {
		return nil, err
	}
	set, err := c.tokenSet(out)
	if err != nil {
		return nil, err
	}
	if set.RefreshToken == "" {
		set.RefreshToken = refreshToken
	}
	return set, nil
}

// Revoke asks the upstream IdP to revoke token (RFC 7009 Section 2.1); tokenTypeHint is access_token, refresh_token or "".
func (c *Client) Revoke(ctx context.Context, token, tokenTypeHint string) error {
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
	if !strings.EqualFold(strings.TrimSpace(out.TokenType), "Bearer") {
		return nil, &Error{Reason: ReasonTokenExchange, Err: errors.New("the token type is not Bearer")}
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
func (c *Client) tokenSet(out *tokenResponse) (*TokenSet, error) {
	if out.AccessToken == "" {
		return nil, &Error{Reason: ReasonTokenExchange, Err: errors.New("the token response has no access_token")}
	}
	set := &TokenSet{AccessToken: out.AccessToken, RefreshToken: out.RefreshToken, Scopes: slices.Clone(c.cfg.Scopes)}
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
