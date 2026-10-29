package oidcrp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// KeySource reads one issuer's discovery document and signing keys, cached, with key rotation; safe for concurrent use.
type KeySource struct {
	issuer string
	http   *http.Client
	now    func() time.Time

	meta *cache[Metadata]
	keys *cache[jose.JSONWebKeySet]

	mu          sync.Mutex
	lastRefetch time.Time
}

// NewKeySource reads issuer's metadata through httpClient, which should refuse redirects and private hosts; nil uses a default.
func NewKeySource(issuer string, httpClient *http.Client) *KeySource {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout:       defaultTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return &KeySource{
		issuer: issuer, http: httpClient, now: time.Now,
		meta: &cache[Metadata]{policy: metadataPolicy}, keys: &cache[jose.JSONWebKeySet]{policy: jwksPolicy},
	}
}

// WithClock replaces the clock, for tests.
func (s *KeySource) WithClock(now func() time.Time) *KeySource {
	s.now = now
	return s
}

// Issuer is the issuer the source reads.
func (s *KeySource) Issuer() string { return s.issuer }

// HTTPClient is the client the source fetches with, for calls to the issuer's other endpoints.
func (s *KeySource) HTTPClient() *http.Client { return s.http }

// Metadata returns the issuer's discovery document, cached by its Cache-Control.
func (s *KeySource) Metadata(ctx context.Context) (*Metadata, error) {
	return s.meta.get(ctx, s.now(), false, s.fetchMetadata)
}

// SECURITY: OIDC Discovery §4.3, the document must name the configured issuer exactly, or it describes another upstream IdP.
func (s *KeySource) fetchMetadata(ctx context.Context) (*Metadata, http.Header, error) {
	discovery := strings.TrimRight(s.issuer, "/") + "/.well-known/openid-configuration"
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, discovery, http.NoBody)
	if err != nil {
		return nil, nil, &Error{Reason: ReasonDiscovery, Err: err}
	}
	var meta Metadata
	h, err := s.doJSON(r, ReasonDiscovery, &meta)
	switch {
	case err != nil:
		return nil, nil, err
	case meta.Issuer != s.issuer:
		return nil, nil, &Error{Reason: ReasonMisconfigured, Err: errors.New("the discovery issuer does not match")}
	case !sameScheme(s.issuer, meta.AuthorizationEndpoint, meta.TokenEndpoint, meta.JWKSURI),
		!optionalSameScheme(s.issuer, meta.EndSessionEndpoint, meta.IntrospectionEndpoint):
		return nil, nil, &Error{Reason: ReasonDiscovery, Err: errors.New("an endpoint is missing or not on the issuer's scheme")}
	}
	return &meta, h, nil
}

// Key returns the issuer's signing key kid. NOTE: OIDC Core §10.1.1: an unknown kid refetches the JWKS once, at most every 30 s.
func (s *KeySource) Key(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	meta, err := s.Metadata(ctx)
	if err != nil {
		return nil, err
	}
	fetch := func(ctx context.Context) (*jose.JSONWebKeySet, http.Header, error) {
		return s.fetchKeys(ctx, meta.JWKSURI)
	}
	now := s.now()
	set, err := s.keys.get(ctx, now, false, fetch)
	if err != nil {
		return nil, err
	}
	if k := find(set, kid); k != nil {
		return k, nil
	}
	s.mu.Lock()
	limited := now.Sub(s.lastRefetch) < jwksMinRefetch
	if !limited {
		s.lastRefetch = now
	}
	s.mu.Unlock()
	if limited {
		return nil, &Error{Reason: ReasonIDToken, Err: errors.New("unknown kid")}
	}
	if set, err = s.keys.get(ctx, now, true, fetch); err != nil {
		return nil, err
	}
	if k := find(set, kid); k != nil {
		return k, nil
	}
	return nil, &Error{Reason: ReasonIDToken, Err: errors.New("unknown kid")}
}

func (s *KeySource) fetchKeys(ctx context.Context, jwksURI string) (*jose.JSONWebKeySet, http.Header, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, http.NoBody)
	if err != nil {
		return nil, nil, &Error{Reason: ReasonJWKS, Err: err}
	}
	var set jose.JSONWebKeySet
	h, err := s.doJSON(r, ReasonJWKS, &set)
	if err != nil {
		return nil, nil, err
	}
	return &set, h, nil
}

func find(set *jose.JSONWebKeySet, kid string) *jose.JSONWebKey {
	for i, k := range set.Keys {
		if k.KeyID == kid && k.IsPublic() && (k.Use == "" || k.Use == "sig") {
			return &set.Keys[i]
		}
	}
	return nil
}

func (s *KeySource) doJSON(r *http.Request, reason Reason, dst any) (http.Header, error) {
	resp, err := s.http.Do(r)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			reason = ReasonTimeout
		}
		return nil, &Error{Reason: reason, Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	switch {
	case err != nil:
		return nil, &Error{Reason: reason, Err: err}
	case resp.StatusCode != http.StatusOK:
		code := oauthError(resp.StatusCode, body)
		return nil, &Error{Reason: reason, OAuthError: code, Err: fmt.Errorf("status %d", resp.StatusCode)}
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return nil, &Error{Reason: reason, Err: err}
	}
	return resp.Header, nil
}

// NOTE: RFC 6749 §5.2 codes plus RFC 8707's invalid_target (https://www.rfc-editor.org/rfc/rfc6749#section-5.2).
func oauthError(status int, body []byte) string {
	if status != http.StatusBadRequest && status != http.StatusUnauthorized {
		return ""
	}
	var out struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &out) != nil || out.Error == "" {
		return ""
	}
	switch out.Error {
	case "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client",
		"unsupported_grant_type", "invalid_scope", "invalid_target":
		return out.Error
	}
	return "other"
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func optionalSameScheme(issuer string, endpoints ...string) bool {
	for _, e := range endpoints {
		if e != "" && !sameScheme(issuer, e) {
			return false
		}
	}
	return true
}

func sameScheme(issuer string, endpoints ...string) bool {
	scheme := "https://"
	if strings.HasPrefix(issuer, "http://") {
		scheme = "http://"
	}
	for _, e := range endpoints {
		if !strings.HasPrefix(e, scheme) || len(e) == len(scheme) {
			return false
		}
	}
	return true
}
