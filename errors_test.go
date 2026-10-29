package oidcrp

import (
	"errors"
	"fmt"
	"testing"
)

func TestReasonOf(t *testing.T) {
	err := fmt.Errorf("callback: %w", &Error{Reason: ReasonNonce, Err: errors.New("mismatch")})
	if ReasonOf(err) != ReasonNonce {
		t.Fatalf("got %q", ReasonOf(err))
	}
	if ReasonOf(errors.New("x")) != "" {
		t.Fatal("a plain error has no reason")
	}
	if (&Error{Reason: ReasonState}).Error() != "oidcrp: state" || !errors.Is(err, errors.Unwrap(errors.Unwrap(err))) {
		t.Fatal("messages")
	}
}
