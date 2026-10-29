package oidcrptest

import (
	"errors"
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
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
