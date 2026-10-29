package oidcrp

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	retryAfterFailure      = 30 * time.Second
	retryAfterEmptyFailure = 5 * time.Second
)

type ttlPolicy struct {
	floor, ceiling, fallback time.Duration
}

// NOTE: RFC 9111 §5.2.2: max-age, clamped to [floor, ceiling], sets the TTL; no-store and no-cache fall to the floor.
func (p ttlPolicy) of(h http.Header) time.Duration {
	ttl, found := p.fallback, false
	for d := range strings.SplitSeq(strings.ToLower(h.Get("Cache-Control")), ",") {
		d = strings.TrimSpace(d)
		switch {
		case d == "no-store" || d == "no-cache":
			return p.floor
		case strings.HasPrefix(d, "max-age="):
			if s, err := strconv.Atoi(strings.TrimPrefix(d, "max-age=")); err == nil && s >= 0 {
				ttl, found = time.Duration(s)*time.Second, true
			}
		}
	}
	if !found {
		return p.fallback
	}
	return min(max(ttl, p.floor), p.ceiling)
}

// NOTE: concurrent misses share one fetch made outside the lock, and a failed refetch serves the last good copy.
type cache[T any] struct {
	policy  ttlPolicy
	timeout time.Duration
	group   singleflight.Group

	mu      sync.Mutex
	val     *T
	err     error
	expires time.Time
	retryAt time.Time
}

func (c *cache[T]) get(
	ctx context.Context, clock func() time.Time, force bool, fetch func(context.Context) (*T, http.Header, error),
) (*T, error) {
	now := clock()
	c.mu.Lock()
	val, failed, fresh, waiting := c.val, c.err, now.Before(c.expires), now.Before(c.retryAt)
	c.mu.Unlock()
	switch {
	case val != nil && (fresh && !force || waiting):
		return val, nil
	case val == nil && waiting:
		return nil, failed
	}
	ch := c.group.DoChan("", func() (any, error) {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cmp.Or(c.timeout, defaultTimeout))
		defer cancel()
		v, h, err := fetch(fctx)
		return c.store(clock(), v, h, err)
	})
	select {
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, &Error{Reason: ReasonCancelled, Err: ctx.Err()}
		}
		return nil, &Error{Reason: ReasonTimeout, Err: ctx.Err()}
	case r := <-ch:
		v, _ := r.Val.(*T)
		return v, r.Err
	}
}

func (c *cache[T]) store(now time.Time, v *T, h http.Header, err error) (*T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case err == nil:
		c.val, c.err, c.expires, c.retryAt = v, nil, now.Add(c.policy.of(h)), time.Time{}
	case c.val == nil:
		c.err, c.retryAt = err, now.Add(retryAfterEmptyFailure)
		return nil, err
	default:
		c.retryAt = now.Add(retryAfterFailure)
	}
	return c.val, nil
}
