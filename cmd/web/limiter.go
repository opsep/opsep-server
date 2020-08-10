package main

import (
	"sync"
	"time"
)

// https://www.alexedwards.net/blog/how-to-rate-limit-http-requests

type Limiter struct {
	DecryptsAllowedPerPeriod int
	DecryptsUsedInPeriod     int
	PeriodInSeconds          int
	PeriodExpiresAt          time.Time
}

var GlobalLimiter Limiter
var mu sync.Mutex

func InitLimiter() {
	expTime := time.Now().Local().Add(time.Second * time.Duration(CFG.PeriodInSeconds))
	GlobalLimiter = Limiter{
		DecryptsAllowedPerPeriod: CFG.DecryptsAllowedPerPeriod,
		DecryptsUsedInPeriod:     0,
		PeriodInSeconds:          CFG.PeriodInSeconds,
		PeriodExpiresAt:          expTime,
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

func AllowThisDecryption() bool {
	mu.Lock()
	defer mu.Unlock()

	// If the limiter is expired then we refresh it and allow the decryption
	if GlobalLimiter.isExpired() {
		InitLimiter()
	}

	if GlobalLimiter.DecryptsUsedInPeriod >= GlobalLimiter.DecryptsAllowedPerPeriod {
		return false
	} else {
		GlobalLimiter.DecryptsUsedInPeriod = GlobalLimiter.DecryptsUsedInPeriod + 1
		return true
	}

}
