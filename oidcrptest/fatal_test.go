package oidcrptest

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingTB struct {
	testing.TB
	fatal string
}

func (r *recordingTB) Helper() {}

func (r *recordingTB) Fatal(args ...any) {
	r.fatal = fmt.Sprint(args...)
	runtime.Goexit()
}

func TestFatal_FailsTheTest(t *testing.T) {
	tb := &recordingTB{}
	f := &IDP{t: tb}
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.fatal(errors.New("signing failed"))
	}()
	<-done
	assert.Equal(t, "signing failed", tb.fatal, "a failing helper fails the test once, never recursing")
}

func TestFatal_PanicsWithoutATest(t *testing.T) {
	f := &IDP{}
	assert.PanicsWithError(t, "signing failed", func() { f.fatal(errors.New("signing failed")) })
}

func TestToken_SigningFailureAnswers500(t *testing.T) {
	f := New(t)
	f.Claims = map[string]any{"broken": make(chan int)}
	verifier := rand.Text()
	sum := sha256.Sum256([]byte(verifier))
	q := f.Authorize("https://idp.example/authorize?" + url.Values{
		"client_id": {"app"}, "redirect_uri": {"https://app.example/cb"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
	}.Encode())
	resp, err := f.Client().PostForm(f.Issuer()+"/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "code_verifier": {verifier},
		"client_id": {"app"}, "redirect_uri": {"https://app.example/cb"},
	})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode, "a handler never fails the test off its goroutine")
}
