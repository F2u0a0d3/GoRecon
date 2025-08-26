package ratelimit

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/config"
	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"
)

type Limiter interface {
	Wait(ctx context.Context) error
	Allow() bool
	Reserve() *rate.Reservation
	GetStats() LimiterStats
}

type Manager struct {
	limiters map[string]Limiter
	config   *config.Config
	mutex    sync.RWMutex
	stats    ManagerStats
}

type LimiterConfig struct {
	RequestsPerSecond float64
	BurstSize         int
	HumanMode         bool
	JitterEnabled     bool
	JitterRange       time.Duration
	BackoffEnabled    bool
	BackoffMultiplier float64
	MaxBackoffTime    time.Duration
}

type LimiterStats struct {
	TotalRequests   int64         `json:"total_requests"`
	AllowedRequests int64         `json:"allowed_requests"`
	BlockedRequests int64         `json:"blocked_requests"`
	AverageWaitTime time.Duration `json:"average_wait_time"`
	LastUsed        time.Time     `json:"last_used"`
}

type ManagerStats struct {
	TotalLimiters   int                    `json:"total_limiters"`
	ActiveLimiters  int                    `json:"active_limiters"`
	LimiterStats    map[string]LimiterStats `json:"limiter_stats"`
	TotalRequests   int64                  `json:"total_requests"`
	TotalWaitTime   time.Duration          `json:"total_wait_time"`
}

type TokenBucketLimiter struct {
	limiter *rate.Limiter
	config  LimiterConfig
	stats   LimiterStats
	mutex   sync.RWMutex
}

type AdaptiveLimiter struct {
	baseLimiter    *rate.Limiter
	config         LimiterConfig
	stats          LimiterStats
	successCount   int64
	errorCount     int64
	lastAdjustment time.Time
	currentRate    float64
	mutex          sync.RWMutex
}

type HumanLimiter struct {
	config LimiterConfig
	stats  LimiterStats
	mutex  sync.RWMutex
	rng    *rand.Rand
}

func NewManager(cfg *config.Config) *Manager {
	return &Manager{
		limiters: make(map[string]Limiter),
		config:   cfg,
		stats: ManagerStats{
			LimiterStats: make(map[string]LimiterStats),
		},
	}
}

func (m *Manager) GetLimiter(name string, config LimiterConfig) Limiter {
	m.mutex.RLock()
	if limiter, exists := m.limiters[name]; exists {
		m.mutex.RUnlock()
		return limiter
	}
	m.mutex.RUnlock()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Double-check pattern
	if limiter, exists := m.limiters[name]; exists {
		return limiter
	}

	var limiter Limiter
	if config.HumanMode {
		limiter = NewHumanLimiter(config)
	} else {
		limiter = NewTokenBucketLimiter(config)
	}

	m.limiters[name] = limiter
	m.stats.TotalLimiters++

	log.Debug().
		Str("limiter", name).
		Float64("rps", config.RequestsPerSecond).
		Bool("human_mode", config.HumanMode).
		Msg("Created rate limiter")

	return limiter
}

func (m *Manager) GetAdaptiveLimiter(name string, config LimiterConfig) *AdaptiveLimiter {
	m.mutex.RLock()
	if limiter, exists := m.limiters[name]; exists {
		if adaptive, ok := limiter.(*AdaptiveLimiter); ok {
			m.mutex.RUnlock()
			return adaptive
		}
	}
	m.mutex.RUnlock()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Double-check pattern
	if limiter, exists := m.limiters[name]; exists {
		if adaptive, ok := limiter.(*AdaptiveLimiter); ok {
			return adaptive
		}
	}

	limiter := NewAdaptiveLimiter(config)
	m.limiters[name] = limiter
	m.stats.TotalLimiters++

	log.Debug().
		Str("limiter", name).
		Float64("base_rps", config.RequestsPerSecond).
		Msg("Created adaptive rate limiter")

	return limiter
}

func (m *Manager) RemoveLimiter(name string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.limiters[name]; exists {
		delete(m.limiters, name)
		delete(m.stats.LimiterStats, name)
		m.stats.TotalLimiters--
		
		log.Debug().Str("limiter", name).Msg("Removed rate limiter")
	}
}

func (m *Manager) GetStats() ManagerStats {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	stats := m.stats
	stats.ActiveLimiters = len(m.limiters)
	stats.LimiterStats = make(map[string]LimiterStats)

	for name, limiter := range m.limiters {
		stats.LimiterStats[name] = limiter.GetStats()
	}

	return stats
}

// Token Bucket Limiter Implementation

func NewTokenBucketLimiter(config LimiterConfig) *TokenBucketLimiter {
	burstSize := config.BurstSize
	if burstSize <= 0 {
		burstSize = int(config.RequestsPerSecond) + 1
	}

	return &TokenBucketLimiter{
		limiter: rate.NewLimiter(rate.Limit(config.RequestsPerSecond), burstSize),
		config:  config,
		stats:   LimiterStats{},
	}
}

func (tbl *TokenBucketLimiter) Wait(ctx context.Context) error {
	start := time.Now()
	
	tbl.mutex.Lock()
	tbl.stats.TotalRequests++
	tbl.mutex.Unlock()

	err := tbl.limiter.Wait(ctx)
	
	waitTime := time.Since(start)
	
	tbl.mutex.Lock()
	if err == nil {
		tbl.stats.AllowedRequests++
		
		// Update average wait time
		if tbl.stats.AllowedRequests == 1 {
			tbl.stats.AverageWaitTime = waitTime
		} else {
			tbl.stats.AverageWaitTime = (tbl.stats.AverageWaitTime*time.Duration(tbl.stats.AllowedRequests-1) + waitTime) / time.Duration(tbl.stats.AllowedRequests)
		}
	} else {
		tbl.stats.BlockedRequests++
	}
	tbl.stats.LastUsed = time.Now()
	tbl.mutex.Unlock()

	// Add jitter if enabled
	if err == nil && tbl.config.JitterEnabled {
		jitter := time.Duration(rand.Int63n(int64(tbl.config.JitterRange)))
		time.Sleep(jitter)
	}

	return err
}

func (tbl *TokenBucketLimiter) Allow() bool {
	tbl.mutex.Lock()
	defer tbl.mutex.Unlock()
	
	tbl.stats.TotalRequests++
	
	if tbl.limiter.Allow() {
		tbl.stats.AllowedRequests++
		tbl.stats.LastUsed = time.Now()
		return true
	}
	
	tbl.stats.BlockedRequests++
	return false
}

func (tbl *TokenBucketLimiter) Reserve() *rate.Reservation {
	tbl.mutex.Lock()
	defer tbl.mutex.Unlock()
	
	tbl.stats.TotalRequests++
	reservation := tbl.limiter.Reserve()
	
	if reservation.OK() {
		tbl.stats.AllowedRequests++
		tbl.stats.LastUsed = time.Now()
	} else {
		tbl.stats.BlockedRequests++
	}
	
	return reservation
}

func (tbl *TokenBucketLimiter) GetStats() LimiterStats {
	tbl.mutex.RLock()
	defer tbl.mutex.RUnlock()
	return tbl.stats
}

// Adaptive Limiter Implementation

func NewAdaptiveLimiter(config LimiterConfig) *AdaptiveLimiter {
	burstSize := config.BurstSize
	if burstSize <= 0 {
		burstSize = int(config.RequestsPerSecond) + 1
	}

	return &AdaptiveLimiter{
		baseLimiter:    rate.NewLimiter(rate.Limit(config.RequestsPerSecond), burstSize),
		config:         config,
		stats:          LimiterStats{},
		currentRate:    config.RequestsPerSecond,
		lastAdjustment: time.Now(),
	}
}

func (al *AdaptiveLimiter) Wait(ctx context.Context) error {
	start := time.Now()
	
	al.mutex.Lock()
	al.stats.TotalRequests++
	al.mutex.Unlock()

	err := al.baseLimiter.Wait(ctx)
	
	waitTime := time.Since(start)
	
	al.mutex.Lock()
	if err == nil {
		al.stats.AllowedRequests++
		al.successCount++
		
		if al.stats.AllowedRequests == 1 {
			al.stats.AverageWaitTime = waitTime
		} else {
			al.stats.AverageWaitTime = (al.stats.AverageWaitTime*time.Duration(al.stats.AllowedRequests-1) + waitTime) / time.Duration(al.stats.AllowedRequests)
		}
	} else {
		al.stats.BlockedRequests++
	}
	al.stats.LastUsed = time.Now()
	al.mutex.Unlock()

	// Periodically adjust rate based on success/error ratio
	al.adjustRate()

	return err
}

func (al *AdaptiveLimiter) Allow() bool {
	al.mutex.Lock()
	defer al.mutex.Unlock()
	
	al.stats.TotalRequests++
	
	if al.baseLimiter.Allow() {
		al.stats.AllowedRequests++
		al.successCount++
		al.stats.LastUsed = time.Now()
		return true
	}
	
	al.stats.BlockedRequests++
	return false
}

func (al *AdaptiveLimiter) Reserve() *rate.Reservation {
	al.mutex.Lock()
	defer al.mutex.Unlock()
	
	al.stats.TotalRequests++
	reservation := al.baseLimiter.Reserve()
	
	if reservation.OK() {
		al.stats.AllowedRequests++
		al.successCount++
		al.stats.LastUsed = time.Now()
	} else {
		al.stats.BlockedRequests++
	}
	
	return reservation
}

func (al *AdaptiveLimiter) RecordError() {
	al.mutex.Lock()
	defer al.mutex.Unlock()
	al.errorCount++
}

func (al *AdaptiveLimiter) adjustRate() {
	al.mutex.Lock()
	defer al.mutex.Unlock()

	now := time.Now()
	if now.Sub(al.lastAdjustment) < 30*time.Second {
		return // Don't adjust too frequently
	}

	totalRequests := al.successCount + al.errorCount
	if totalRequests < 10 {
		return // Need more data
	}

	errorRate := float64(al.errorCount) / float64(totalRequests)
	
	var newRate float64
	if errorRate > 0.1 { // More than 10% errors, slow down
		newRate = al.currentRate * 0.8
	} else if errorRate < 0.05 { // Less than 5% errors, speed up
		newRate = al.currentRate * 1.1
	} else {
		return // No adjustment needed
	}

	// Clamp to reasonable bounds
	minRate := al.config.RequestsPerSecond * 0.1
	maxRate := al.config.RequestsPerSecond * 2.0
	
	if newRate < minRate {
		newRate = minRate
	} else if newRate > maxRate {
		newRate = maxRate
	}

	if newRate != al.currentRate {
		al.currentRate = newRate
		al.baseLimiter.SetLimit(rate.Limit(newRate))
		al.lastAdjustment = now
		
		// Reset counters
		al.successCount = 0
		al.errorCount = 0

		log.Debug().
			Float64("old_rate", al.currentRate).
			Float64("new_rate", newRate).
			Float64("error_rate", errorRate).
			Msg("Adjusted adaptive rate limiter")
	}
}

func (al *AdaptiveLimiter) GetStats() LimiterStats {
	al.mutex.RLock()
	defer al.mutex.RUnlock()
	return al.stats
}

func (al *AdaptiveLimiter) GetCurrentRate() float64 {
	al.mutex.RLock()
	defer al.mutex.RUnlock()
	return al.currentRate
}

// Human Limiter Implementation

func NewHumanLimiter(config LimiterConfig) *HumanLimiter {
	return &HumanLimiter{
		config: config,
		stats:  LimiterStats{},
		rng:    rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (hl *HumanLimiter) Wait(ctx context.Context) error {
	start := time.Now()
	
	hl.mutex.Lock()
	hl.stats.TotalRequests++
	hl.mutex.Unlock()

	// Human-like delays: random intervals with realistic patterns
	baseDelay := time.Duration(float64(time.Second) / hl.config.RequestsPerSecond)
	
	// Add human-like variation (normal distribution around base delay)
	variation := time.Duration(hl.rng.NormFloat64() * float64(baseDelay) * 0.3)
	humanDelay := baseDelay + variation
	
	// Ensure minimum and maximum delays
	if humanDelay < 100*time.Millisecond {
		humanDelay = 100*time.Millisecond
	} else if humanDelay > 30*time.Second {
		humanDelay = 30*time.Second
	}

	// Occasionally add longer pauses to simulate human breaks
	if hl.rng.Float64() < 0.05 { // 5% chance
		humanDelay += time.Duration(hl.rng.Intn(10)+1) * time.Second
	}

	select {
	case <-ctx.Done():
		hl.mutex.Lock()
		hl.stats.BlockedRequests++
		hl.mutex.Unlock()
		return ctx.Err()
	case <-time.After(humanDelay):
		waitTime := time.Since(start)
		
		hl.mutex.Lock()
		hl.stats.AllowedRequests++
		if hl.stats.AllowedRequests == 1 {
			hl.stats.AverageWaitTime = waitTime
		} else {
			hl.stats.AverageWaitTime = (hl.stats.AverageWaitTime*time.Duration(hl.stats.AllowedRequests-1) + waitTime) / time.Duration(hl.stats.AllowedRequests)
		}
		hl.stats.LastUsed = time.Now()
		hl.mutex.Unlock()
		
		return nil
	}
}

func (hl *HumanLimiter) Allow() bool {
	hl.mutex.Lock()
	defer hl.mutex.Unlock()
	
	hl.stats.TotalRequests++
	
	// Simple implementation for non-blocking check
	// In human mode, we generally allow but track for stats
	hl.stats.AllowedRequests++
	hl.stats.LastUsed = time.Now()
	return true
}

func (hl *HumanLimiter) Reserve() *rate.Reservation {
	// For human limiter, we don't use reservations
	// Return a dummy reservation that's always OK
	return &rate.Reservation{}
}

func (hl *HumanLimiter) GetStats() LimiterStats {
	hl.mutex.RLock()
	defer hl.mutex.RUnlock()
	return hl.stats
}

// Utility functions for common rate limiting patterns

func GetGlobalLimiter(manager *Manager, rps float64) Limiter {
	return manager.GetLimiter("global", LimiterConfig{
		RequestsPerSecond: rps,
		BurstSize:         int(rps) + 1,
		HumanMode:         false,
		JitterEnabled:     true,
		JitterRange:       100 * time.Millisecond,
	})
}

func GetPluginLimiter(manager *Manager, pluginID string, rps float64, humanMode bool) Limiter {
	return manager.GetLimiter(fmt.Sprintf("plugin-%s", pluginID), LimiterConfig{
		RequestsPerSecond: rps,
		BurstSize:         int(rps) + 1,
		HumanMode:         humanMode,
		JitterEnabled:     true,
		JitterRange:       200 * time.Millisecond,
	})
}

func GetDomainLimiter(manager *Manager, domain string, rps float64) Limiter {
	return manager.GetLimiter(fmt.Sprintf("domain-%s", domain), LimiterConfig{
		RequestsPerSecond: rps,
		BurstSize:         int(rps) + 1,
		HumanMode:         false,
		JitterEnabled:     true,
		JitterRange:       500 * time.Millisecond,
	})
}

func GetAdaptiveDomainLimiter(manager *Manager, domain string, baseRPS float64) *AdaptiveLimiter {
	return manager.GetAdaptiveLimiter(fmt.Sprintf("adaptive-%s", domain), LimiterConfig{
		RequestsPerSecond: baseRPS,
		BurstSize:         int(baseRPS) + 1,
		BackoffEnabled:    true,
		BackoffMultiplier: 2.0,
		MaxBackoffTime:    60 * time.Second,
	})
}