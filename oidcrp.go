package oidcrp

import (
	"net/http"
	"time"
)

// Config is one relying party's registration at one upstream IdP (an OpenID Provider).
type Config struct {
	// Issuer is the upstream IdP's issuer; its discovery document is read from Issuer + "/.well-known/openid-configuration".
	Issuer   string
	ClientID string
	// ClientSecret empty sends client_id in the body, no Basic (https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1).
	ClientSecret string
	RedirectURI  string
	Scopes       []string
	// AcceptIssuers are further iss forms the upstream IdP puts in ID tokens (Google's "accounts.google.com").
	AcceptIssuers []string
	HTTPClient    *http.Client
	ClockSkew     time.Duration
	// Resource is the RFC 8707 resource indicator sent on the authorization, code and refresh requests; "" sends none.
	Resource string
}

// Metadata is the part of the upstream IdP's discovery document the relying party uses (OIDC Discovery §3).
type Metadata struct {
	Issuer                         string   `json:"issuer"`
	AuthorizationEndpoint          string   `json:"authorization_endpoint"`
	TokenEndpoint                  string   `json:"token_endpoint"`
	JWKSURI                        string   `json:"jwks_uri"`
	CodeChallengeMethodsSupported  []string `json:"code_challenge_methods_supported"`
	AuthorizationResponseISSParams bool     `json:"authorization_response_iss_parameter_supported"`
	IDTokenSigningAlgValues        []string `json:"id_token_signing_alg_values_supported"`
	EndSessionEndpoint             string   `json:"end_session_endpoint"`
	IntrospectionEndpoint          string   `json:"introspection_endpoint"`
	RevocationEndpoint             string   `json:"revocation_endpoint"`
}

// AuthRequest is one sign-in attempt: the values kept on the browser until the callback, never sent to the client.
type AuthRequest struct {
	State        string
	Nonce        string
	CodeVerifier string
	Prompt       string
	LoginHint    string
}

// Callback is the authorization response the upstream IdP sent to the redirect URI.
type Callback struct {
	Code             string
	State            string
	Issuer           string
	Error            string
	ErrorDescription string
}

// IDToken is a validated ID token's claims the relying party reads.
type IDToken struct {
	Issuer        string
	Subject       string
	Audience      []string
	Email         string
	EmailVerified bool
	Name          string
	HostedDomain  string
	IssuedAt      time.Time
	ExpiresAt     time.Time
	// AuthTime is when the person signed in at the upstream IdP; zero when the token has no auth_time.
	AuthTime  time.Time
	SessionID string
	// Raw is the compact ID token, the id_token_hint for an RP-initiated logout.
	Raw string
}

// TokenSet is a validated token response (RFC 6749 Section 5.1).
type TokenSet struct {
	// IDToken is the verified ID token of a sign-in; nil after a refresh.
	IDToken     *IDToken
	AccessToken string
	// RefreshToken is the one to use next: the new one, or the presented one when a refresh issued none (RFC 6749 Section 6).
	RefreshToken string
	// ExpiresAt is when the access token expires, from expires_in; zero when the response had none.
	ExpiresAt time.Time
	// Scopes are the granted scopes, or the requested ones when the response left scope out (RFC 6749 Section 5.1).
	Scopes []string
}
