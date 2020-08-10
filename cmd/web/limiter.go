package main

import (
	"sync"
	"time"
)

// https://www.alexedwards.net/blog/how-to-rate-limit-http-requests

type Limiter struct {
	APIToken                 string
	DecryptsAllowedPerPeriod int
	DecryptsUsedInPeriod     int
	PeriodInSeconds          int
	PeriodExpiresAt          time.Time
	AccessMu                 sync.Mutex
}

// Create a map to hold the rate limiters for each visitor and a mutex.
var limiters = make(map[string]*Limiter)
var mu sync.Mutex

func NewLimiter(decryptsAllowedPerPeriod int, decryptsUsedInPeriod int, periodInSeconds int, periodExpiresAt time.Time) *Limiter {
	return &Limiter{
		DecryptsAllowedPerPeriod: decryptsAllowedPerPeriod,
		DecryptsUsedInPeriod:     decryptsUsedInPeriod,
		PeriodInSeconds:          periodInSeconds,
		PeriodExpiresAt:          periodExpiresAt,
	}
}

func (l *Limiter) isExpired() bool {
	return l.PeriodExpiresAt.Before(time.Now().Local())
}

func (l *Limiter) callsRemaining() int {
	return l.DecryptsAllowedPerPeriod - l.DecryptsUsedInPeriod
}

func (l *Limiter) secondsToExpiry() int {
	currTime := time.Now().Local()
	seconds := l.PeriodExpiresAt.Sub(currTime).Seconds()
	if seconds > 0 {
		return int(seconds)
	} else {
		return -1
	}
}

// Retrieve and return the rate limiter for the current visitor if it
// already exists. Otherwise create a new rate limiter and add it to
// the visitors map, using the IP address as the key.
func getLimiter(apiToken string) *Limiter {
	mu.Lock()
	defer mu.Unlock()

	limiter, exists := limiters[apiToken]
	if exists {
		// TODO: combine into one
		if !limiter.isExpired() {
			return limiter
		}
	}

	// FIXME: don't hardcode (query DB without slowing down the lock for everyone else)
	expTime := time.Now().Local().Add(time.Second * time.Duration(600))
	newL := NewLimiter(100, 0, 600, expTime)
	limiters[apiToken] = newL

	return newL
}

func (l *Limiter) incrementLimiter() bool {

	// If the limiter is expired (and the API token is still valid) then we can allow a request

	if l.isExpired() {
		mu.Lock()
		defer mu.Unlock()

		// FIXME: don't hardcode (query DB without slowing down the lock for everyone else)
		expTime := time.Now().Local().Add(time.Second * time.Duration(600))
		newL := NewLimiter(100, 1, 600, expTime)
		limiters[l.APIToken] = newL
		return true
	}

	if l.DecryptsUsedInPeriod >= l.DecryptsAllowedPerPeriod {
		return false
	}

	l.AccessMu.Lock()
	defer l.AccessMu.Unlock()

	l.DecryptsUsedInPeriod = l.DecryptsUsedInPeriod + 1

	return true

}
