package httprps

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const windowSize = 60 // Sliding window size in seconds

type Middleware struct {
	wrapped http.Handler

	curr int64

	mu         sync.Mutex
	counts     []int64
	currentIdx int
	total      int64
}

func NewMiddleware(wrap http.Handler) *Middleware {
	m := &Middleware{
		wrapped: wrap,

		counts: make([]int64, windowSize),
	}

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		for {
			<-ticker.C
			newCount := atomic.SwapInt64(&m.curr, 0)

			m.mu.Lock()
			m.total -= m.counts[m.currentIdx]
			m.counts[m.currentIdx] = newCount
			m.total += newCount
			m.currentIdx = (m.currentIdx + 1) % windowSize
			m.mu.Unlock()
		}
	}()

	return m
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&m.curr, 1)
	m.wrapped.ServeHTTP(w, r)
}

func (m *Middleware) GetRPS() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	return float64(m.total) / windowSize
}
