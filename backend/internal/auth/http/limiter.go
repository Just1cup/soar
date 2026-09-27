package http

import (
	"strings"
	"sync"
	"time"
)

// LoginLimiter bounds password work and online guessing in the edge profile.
// It is deliberately small and in-process; a multi-replica profile replaces
// this adapter with a shared limiter without changing the handler contract.
type LoginLimiter struct {
	source  *windowLimiter
	account *windowLimiter
}

type windowLimiter struct {
	mu      sync.Mutex
	window  time.Duration
	max     int
	entries map[string]attempts
	// nextSweep cresce geometricamente depois de cada varredura. Sem isso,
	// com N chaves vivas a varredura roda a cada chamada e não libera nada:
	// O(n) por inserção, O(n²) no total. Custou 91 s num teste unitário.
	nextSweep int
	lastSweep time.Time
}

type attempts struct {
	start time.Time
	count int
}

// Sem poda, o mapa cresce com cada chave distinta e o próprio limitador vira
// o vetor de exaustão de memória que ele existe para conter: basta pulverizar
// e-mails inventados. A varredura é amortizada — só acontece quando o mapa
// passa do limiar — e remove o que já expirou, que é a maioria.
const (
	sweepThreshold = 4096
	hardCap        = 65536
)

func NewLoginLimiter(accountMax, sourceMax int, window time.Duration) *LoginLimiter {
	return &LoginLimiter{
		account: newWindowLimiter(accountMax, window),
		source:  newWindowLimiter(sourceMax, window),
	}
}

func newWindowLimiter(max int, window time.Duration) *windowLimiter {
	return &windowLimiter{
		max: max, window: window,
		entries:   make(map[string]attempts),
		nextSweep: sweepThreshold,
	}
}

// Allow checks independent account and source buckets. A combined
// "IP|account" bucket would let one IP spray one password across unlimited
// accounts, while an IP-only bucket lets one user lock out everyone behind a
// corporate proxy.
func (l *LoginLimiter) Allow(source, account string, now time.Time) bool {
	return l.source.allow(source, now) && l.account.allow(strings.ToLower(account), now)
}

func (l *windowLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Duas condições, porque só o tamanho não basta: depois de uma rajada, um
	// sistema ocioso seguraria as entradas vencidas para sempre.
	if len(l.entries) >= l.nextSweep || now.Sub(l.lastSweep) >= l.window {
		l.sweepLocked(now)
	}
	a := l.entries[key]
	if a.start.IsZero() || now.Sub(a.start) >= l.window {
		a = attempts{start: now}
	}
	if a.count >= l.max {
		l.entries[key] = a
		return false
	}
	a.count++
	l.entries[key] = a
	return true
}

// ResetAccount forgives the account bucket after a valid login. The source
// bucket is intentionally retained so cycling through a known-good account
// cannot erase evidence of a credential-stuffing burst.
func (l *LoginLimiter) ResetAccount(account string) {
	l.account.reset(strings.ToLower(account))
}

// sweepLocked descarta janelas já vencidas. Se mesmo assim o mapa continuar
// acima do teto rígido, ele é zerado: perder contagem sob um ataque
// distribuído é ruim, perder o processo é pior — e chegar aqui exige dezenas
// de milhares de chaves vivas dentro da janela, o que já passou pelo balde de
// origem.
func (l *windowLimiter) sweepLocked(now time.Time) {
	for k, a := range l.entries {
		if now.Sub(a.start) >= l.window {
			delete(l.entries, k)
		}
	}
	if len(l.entries) >= hardCap {
		clear(l.entries)
	}
	l.nextSweep = max(sweepThreshold, len(l.entries)*2)
	l.lastSweep = now
}

// size existe para o teste poder afirmar que a poda acontece.
func (l *windowLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

func (l *windowLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.entries, key)
	l.mu.Unlock()
}
