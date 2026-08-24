package serve

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestListCerts_PaginationLimit verifies GET /api/v1/certs limit/offset pagination works
// (fix: previously the limit parameter was ignored, returning all results causing the large CA list endpoint to take hundreds of ms).
func TestListCerts_PaginationLimit(t *testing.T) {
	_, _, h := newTestServerFull7(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	token := loginAsAdmin7(t, ts)
	if token == "" {
		t.Skip("login failed")
	}

	const n = 6
	for i := 0; i < n; i++ {
		body, _ := json.Marshal(map[string]interface{}{
			"cn":      fmt.Sprintf("page-api-%d.example.com", i),
			"ca":      "test-ca",
			"profile": "tls-server",
		})
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1/certs", bytes.NewReader(body))
		req.Header.Set("X-Auth-Token", token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("issue %d failed: %d", i, resp.StatusCode)
		}
	}

	get := func(q string) int {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/certs?ca=test-ca"+q, nil)
		req.Header.Set("X-Auth-Token", token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list got %d", resp.StatusCode)
		}
		var list []jsonCert
		if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
			t.Fatal(err)
		}
		return len(list)
	}

	if got := get("&limit=2"); got != 2 {
		t.Fatalf("limit=2: expected 2, got %d", got)
	}
	if got := get("&limit=2&offset=2"); got != 2 {
		t.Fatalf("limit=2&offset=2: expected 2, got %d", got)
	}
	if got := get("&limit=2&offset=5"); got != 1 {
		t.Fatalf("limit=2&offset=5 (tail): expected 1, got %d", got)
	}
	if got := get("&limit=0"); got != n {
		t.Fatalf("limit=0 (no paging): expected %d, got %d", n, got)
	}
	if got := get("&limit=9999"); got != n {
		t.Fatalf("limit=9999: expected %d, got %d", n, got)
	}
	// Default limit=50 should not truncate small datasets
	if got := get(""); got != n {
		t.Fatalf("default limit: expected %d, got %d", n, got)
	}
}
