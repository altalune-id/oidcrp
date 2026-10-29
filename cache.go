package oidcrp

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const retryAfterFailure = 30 * time.Second

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
	policy ttlPolicy
	group  singleflight.Group

	mu      sync.Mutex
	val     *T
	expires time.Time
	retryAt time.Time
}

type fetched[T any] struct {
	val    *T
	header http.Header
}

func (c *cache[T]) get(ctx context.Context, now time.Time, force bool, fetch func(context.Context) (*T, http.Header, error)) (*T, error) {
	c.mu.Lock()
	val, fresh, waiting := c.val, now.Before(c.expires), now.Before(c.retryAt)
	c.mu.Unlock()
	if val != nil && (fresh && !force || waiting) {
		return val, nil
	}
	got, err, _ := c.group.Do("", func() (any, error) {
		v, h, err := fetch(context.WithoutCancel(ctx))
		return fetched[T]{val: v, header: h}, err
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		if c.val == nil {
			return nil, err
		}
		c.retryAt = now.Add(retryAfterFailure)
		return c.val, nil
	}
	f := got.(fetched[T]) //nolint:forcetypeassert // the group only ever stores fetched[T].
	c.val, c.expires, c.retryAt = f.val, now.Add(c.policy.of(f.header)), time.Time{}
	return c.val, nil
}
