package serve

import (
	"sync"
	"testing"
)

func TestRateLimiterAllow(t *testing.T) {
	rl := NewRateLimiter(100, 10)

	if !rl.Allow("127.0.0.1") {
		t.Fatal("expected first request to be allowed")
	}
}

func TestRateLimiterDeny(t *testing.T) {
	rl := NewRateLimiter(1, 1)

	if !rl.Allow("192.168.1.1") {
		t.Fatal("expected first request to be allowed (burst=1)")
	}
	if rl.Allow("192.168.1.1") {
		t.Fatal("expected second request to be denied (burst exhausted)")
	}
}

func TestRateLimiterBurst(t *testing.T) {
	rl := NewRateLimiter(10, 5)

	for i := 0; i < 5; i++ {
		if !rl.Allow("10.0.0.1") {
			t.Fatalf("expected request %d to be allowed (burst=5)", i+1)
		}
	}
}

func TestRateLimiterDifferentIPs(t *testing.T) {
	rl := NewRateLimiter(1, 1)

	if !rl.Allow("ip-a") {
		t.Fatal("expected ip-a to be allowed")
	}
	if !rl.Allow("ip-b") {
		t.Fatal("expected ip-b to be allowed (different IP)")
	}
}

func TestRateLimiterConcurrent(t *testing.T) {
	rl := NewRateLimiter(1000, 100)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ip := "10.0.0.1"
			for j := 0; j < 5; j++ {
				rl.Allow(ip)
			}
		}(i)
	}
	wg.Wait()
}
