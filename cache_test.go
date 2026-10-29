package oidcrp

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCache_CallerCancelsAHungFetch(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	c := cache[Metadata]{timeout: 200 * time.Millisecond}
	fetch := func(ctx context.Context) (*Metadata, http.Header, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, nil, errors.New("hung")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.get(ctx, at(now), false, fetch)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Equal(t, ReasonTimeout, ReasonOf(err))
	assert.Less(t, time.Since(start), 2*time.Second, "returns when the caller's context ends, not when the upstream answers")
}

func TestCache_BacksOffWhenEmpty(t *testing.T) {
	var c cache[Metadata]
	var calls atomic.Int32
	fetch := func(context.Context) (*Metadata, http.Header, error) {
		calls.Add(1)
		return nil, nil, &Error{Reason: ReasonDiscovery, Err: errors.New("status 503")}
	}
	_, err := c.get(context.Background(), at(now), false, fetch)
	require.Error(t, err)
	_, again := c.get(context.Background(), at(now.Add(time.Second)), false, fetch)
	assert.Equal(t, err, again, "the cached failure is answered during the back-off")
	assert.Equal(t, int32(1), calls.Load())

	_, err = c.get(context.Background(), at(now.Add(retryAfterEmptyFailure)), false, fetch)
	require.Error(t, err)
	assert.Equal(t, int32(2), calls.Load(), "after the back-off it tries again")
}

func TestCache_BackOffStartsWhenASlowFetchEnds(t *testing.T) {
	var c cache[Metadata]
	base := time.Now()
	advancing := func() time.Time { return now.Add(time.Since(base)) }
	var calls atomic.Int32
	fetch := func(context.Context) (*Metadata, http.Header, error) {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond)
		return nil, nil, &Error{Reason: ReasonTimeout, Err: errors.New("hung")}
	}
	_, err := c.get(context.Background(), advancing, false, fetch)
	require.Error(t, err)
	_, err = c.get(context.Background(), at(now.Add(retryAfterEmptyFailure)), false, fetch)
	require.Error(t, err)
	assert.Equal(t, int32(1), calls.Load(), "the back-off counts from when the failed fetch ended, not when it started")
}

func TestCache_CancelledCaller(t *testing.T) {
	c := cache[Metadata]{timeout: 200 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.get(ctx, at(now), false, func(fctx context.Context) (*Metadata, http.Header, error) {
		<-fctx.Done()
		return nil, nil, fctx.Err()
	})
	assert.Equal(t, ReasonCancelled, ReasonOf(err))
}

func at(t time.Time) func() time.Time { return func() time.Time { return t } }
