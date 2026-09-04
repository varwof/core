// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import "testing"

// RFC 5280 §7.4 URI-host name constraint matching.
func TestURIHostIn(t *testing.T) {
	cases := []struct {
		name       string
		constraint string
		host       string
		want       bool
	}{
		{"dot matches subdomain", ".example.com", "sub.example.com", true},
		{"dot matches nested", ".example.com", "a.b.example.com", true},
		{"dot rejects apex", ".example.com", "example.com", false},
		{"dot rejects other", ".example.com", "other.org", false},
		{"bare matches exact host", "example.com", "example.com", true},
		{"bare rejects subdomain", "example.com", "sub.example.com", false},
		{"bare rejects other", "example.com", "other.org", false},
		{"host with many labels bare", "host.example.com", "host.example.com", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := uriHostIn(c.constraint, c.host); got != c.want {
				t.Fatalf("uriHostIn(%q, %q) = %v, want %v", c.constraint, c.host, got, c.want)
			}
		})
	}
}

// RFC 5280 §7.4: a URI host specified as an IP address is rejected when URI
// constraints are present.
func TestURIHostMatchRejectsIP(t *testing.T) {
	_, ipHost, _ := uriHostMatch("192.0.2.1", []string{".example.com"}, nil)
	if !ipHost {
		t.Fatal("expected IP host rejected under URI constraints")
	}
	_, ipHost, _ = uriHostMatch("192.0.2.1", nil, nil)
	if ipHost {
		t.Fatal("expected no IP rejection when no URI constraints present")
	}
}

func TestURIHostMatchPermit(t *testing.T) {
	ok, _, reason := uriHostMatch("sub.example.com", []string{".example.com"}, nil)
	if !ok || reason != "" {
		t.Fatalf("expected permitted, got ok=%v reason=%q", ok, reason)
	}
	ok, _, reason = uriHostMatch("example.com", []string{".example.com"}, nil)
	if ok {
		t.Fatal("expected apex rejected under dot constraint")
	}
	ok, _, reason = uriHostMatch("sub.example.com", []string{"example.com"}, nil)
	if ok {
		t.Fatal("expected subdomain rejected under bare constraint")
	}
}

// RFC 5280 §7.5 email name-constraint matching.
func TestEmailAddrIn(t *testing.T) {
	cases := []struct {
		name       string
		constraint string
		addr       string
		want       bool
	}{
		{"mailbox exact", "alice@example.com", "alice@example.com", true},
		{"mailbox wrong user", "alice@example.com", "bob@example.com", false},
		{"bare host at host", "example.com", "alice@example.com", true},
		{"bare host rejects subdomain", "example.com", "alice@sub.example.com", false},
		{"dot domain subdomain", ".example.com", "alice@sub.example.com", true},
		{"dot domain nested", ".example.com", "alice@a.b.example.com", true},
		{"dot domain rejects apex host", ".example.com", "alice@example.com", false},
		{"dot rejects unrelated", ".example.com", "alice@other.org", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := emailAddrIn(c.constraint, c.addr); got != c.want {
				t.Fatalf("emailAddrIn(%q, %q) = %v, want %v", c.constraint, c.addr, got, c.want)
			}
		})
	}
}
