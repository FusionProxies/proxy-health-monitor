package scheduler

import (
	"context"
	"sync"
	"time"

	"github.com/FusionProxies/proxy-health-monitor/internal/config"
)

// Limits enforces the global concurrency limit and, per target, a maximum
// number of checks in flight and a minimum spacing between two checks.
type Limits struct {
	global chan struct{}
	mu     sync.Mutex
	per    map[string]*targetLimit
}

type targetLimit struct {
	sem     chan struct{}
	spacing time.Duration
	mu      sync.Mutex
	next    time.Time
}

// NewLimits builds limits for the configured targets.
func NewLimits(concurrency int, targets []*config.Target) *Limits {
	l := &Limits{global: make(chan struct{}, concurrency), per: map[string]*targetLimit{}}
	for _, t := range targets {
		l.per[t.Name] = &targetLimit{sem: make(chan struct{}, t.MaxConcurrent), spacing: t.MinSpacing.D()}
	}
	return l
}

// Acquire waits until a check against t may start. The returned function
// releases the slot. It fails only when ctx ends.
func (l *Limits) Acquire(ctx context.Context, t *config.Target) (func(), error) {
	l.mu.Lock()
	tl := l.per[t.Name]
	if tl == nil {
		tl = &targetLimit{sem: make(chan struct{}, max(1, t.MaxConcurrent)), spacing: t.MinSpacing.D()}
		l.per[t.Name] = tl
	}
	l.mu.Unlock()

	select {
	case tl.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	tl.mu.Lock()
	now := time.Now()
	startAt := now
	if tl.next.After(now) {
		startAt = tl.next
	}
	tl.next = startAt.Add(tl.spacing)
	tl.mu.Unlock()
	if wait := time.Until(startAt); wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			<-tl.sem
			return nil, ctx.Err()
		}
	}
	select {
	case l.global <- struct{}{}:
	case <-ctx.Done():
		<-tl.sem
		return nil, ctx.Err()
	}
	return func() {
		<-l.global
		<-tl.sem
	}, nil
}
