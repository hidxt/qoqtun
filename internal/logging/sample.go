package logging

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// sampler is a per-window dedup of repeated messages: identical message
// strings within the window are logged at most maxPerWindow times, and then
// suppressed (with a periodic drop counter) until the window rolls.
type sampler struct {
	mu        sync.Mutex
	window    time.Duration
	max       int
	seen      map[string]*sampleState
	lastPrune time.Time
}

type sampleState struct {
	first time.Time
	count int
}

// SamplingHandler wraps h and rate-limits identical messages (anti-log
// flood, T14-adjacent operational guard). dropEvery controls how often a
// suppression summary line is emitted (0 disables the summary).
func SamplingHandler(h slog.Handler, window time.Duration, maxPerWindow int, dropEvery int) slog.Handler {
	if maxPerWindow <= 0 {
		return h
	}
	return &samplingHandler{h: h, s: &sampler{window: window, max: maxPerWindow, seen: make(map[string]*sampleState)}, dropEvery: dropEvery}
}

type samplingHandler struct {
	h         slog.Handler
	s         *sampler
	dropEvery int
}

func (sh *samplingHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return sh.h.Enabled(ctx, l)
}

func (sh *samplingHandler) Handle(ctx context.Context, r slog.Record) error {
	key := r.Message
	now := time.Now()
	sh.s.mu.Lock()
	sh.s.prune(now)
	st, ok := sh.s.seen[key]
	if !ok {
		st = &sampleState{first: now}
		sh.s.seen[key] = st
	}
	st.count++
	allow := st.count <= sh.s.max
	dropped := st.count - sh.s.max
	sh.s.mu.Unlock()
	if allow {
		return sh.h.Handle(ctx, r)
	}
	// suppression summary: emit one line per dropEvery suppressed events
	if sh.dropEvery > 0 && dropped > 0 && dropped%sh.dropEvery == 0 {
		rec := slog.NewRecord(now, slog.LevelWarn, "log flood suppressed: "+key, r.PC)
		rec.AddAttrs(slog.Int("suppressed", dropped))
		return sh.h.Handle(ctx, rec)
	}
	return nil
}

func (sh *samplingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &samplingHandler{h: sh.h.WithAttrs(attrs), s: sh.s, dropEvery: sh.dropEvery}
}

func (sh *samplingHandler) WithGroup(name string) slog.Handler {
	return &samplingHandler{h: sh.h.WithGroup(name), s: sh.s, dropEvery: sh.dropEvery}
}

func (s *sampler) prune(now time.Time) {
	if now.Sub(s.lastPrune) < s.window {
		return
	}
	for k, st := range s.seen {
		if now.Sub(st.first) > s.window {
			delete(s.seen, k)
		}
	}
	s.lastPrune = now
}

// default flood guard: at most 5 identical messages per minute per process,
// with a summary every 200 suppressed.
func DefaultFloodGuard(h slog.Handler) slog.Handler {
	return SamplingHandler(h, time.Minute, 5, 200)
}
