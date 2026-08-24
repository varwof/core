package serve

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/varwof/core/internal/ca"
	"github.com/varwof/core/internal/capregistry"
)

// TestServeCapRegistryHookRejectsUnregistered verifies the issuance-side capability registration validation hook:
// After enabling capReg, AIC declaring unregistered capability → issuance fails (400/5xx), registered capability → success.
func TestServeCapRegistryHookRejectsUnregistered(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)

	// Enable capability registry (embedded approach)
	cr := capregistry.New()
	if err := cr.LoadAndSet("../../../capability/data"); err != nil {
		t.Fatalf("LoadAndSet: %v", err)
	}
	srv.SetCapRegistry(cr)

	ts := httptest.NewServer(srv)
	defer ts.Close()

	// Unregistered capability (varwof-gateway-v1 is not a scheme in the registry)
	body, _ := agentProxyC3Body(t, caCert, caKey, "unreg-agent", "unreg-1",
		[]ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}, 0, nil)

	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(body)))
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("expected non-200 for unregistered capability")
	}
	bb := make([]byte, 512)
	n, _ := resp.Body.Read(bb)
	if !strings.Contains(string(bb[:n]), "capability registration validation") {
		t.Errorf("expected capability registration validation error, got: %s", string(bb[:n]))
	}
}

// TestServeCapRegistryHookAllowsRegistered verifies registered capability passes issuance.
func TestServeCapRegistryHookAllowsRegistered(t *testing.T) {
	srv, _, caCert, caKey := newTestServerWithCA(t)

	cr := capregistry.New()
	if err := cr.LoadAndSet("../../../capability/data"); err != nil {
		t.Fatalf("LoadAndSet: %v", err)
	}
	srv.SetCapRegistry(cr)

	ts := httptest.NewServer(srv)
	defer ts.Close()

	// Registered capability: varwof/gateway:proxy:http
	body, _ := agentProxyC3Body(t, caCert, caKey, "reg-agent", "reg-1",
		[]ca.Capability{{SchemeId: "varwof/gateway", CapabilityId: "proxy:http"}}, 0, nil)

	resp := authedPost(t, ts, "/api/v1/certs", "application/json", strings.NewReader(string(body)))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bb := make([]byte, 512)
		n, _ := resp.Body.Read(bb)
		t.Fatalf("expected 200 for registered capability, got %d: %s", resp.StatusCode, string(bb[:n]))
	}
}
