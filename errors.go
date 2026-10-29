package oidcrp

import "errors"

// Reason is why a sign-in failed, for logs and the upstream error codes; never shown with upstream text.
type Reason string

// The failures of a upstream round trip.
const (
	ReasonDiscovery     Reason = "discovery"
	ReasonJWKS          Reason = "jwks"
	ReasonTokenExchange Reason = "token_exchange"
	ReasonTimeout       Reason = "timeout"
	ReasonState         Reason = "state"
	ReasonIssuer        Reason = "iss"
	ReasonNonce         Reason = "nonce"
	ReasonIDToken       Reason = "id_token"
	ReasonCancelled     Reason = "cancelled"
	ReasonError         Reason = "error"
	// ReasonMisconfigured is the deployment's fault, not the upstream IdP's: discovery names another issuer.
	ReasonMisconfigured Reason = "misconfigured"
)

// Error is a failed upstream round trip with its Reason; Err is the cause, for logs.
type Error struct {
	Reason Reason
	// OAuthError is the RFC 6749 §5.2 error code of a 400 or 401 answer, or "other" for an unknown one; it never carries upstream text.
	OAuthError string
	Err        error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return "oidcrp: " + string(e.Reason)
	}
	return "oidcrp: " + string(e.Reason) + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

// OAuthErrorOf returns the RFC 6749 §5.2 error code in err's tree, or "" when the endpoint sent none.
func OAuthErrorOf(err error) string {
	if e, ok := errors.AsType[*Error](err); ok {
		return e.OAuthError
	}
	return ""
}

// ReasonOf returns the Reason in err's tree, or "" when err is not an *Error.
func ReasonOf(err error) Reason {
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Reason
	}
	return ""
}
