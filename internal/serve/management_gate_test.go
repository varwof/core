package serve

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestManagementMintGate locks down the management sub-CA mint fail-closed gate
// in apiIssueCert: minting an m-* profile certificate requires a live mTLS
// certificate with the superadmin role in hand. Username/password sessions are
// rejected even though basic authentication yields an (operator-level) account.
func TestManagementMintGate(t *testing.T) {
	handler := newTestServer(t)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	const mintBody = `{"profile":"m-superadmin","cn":"gate-probe","ca":"test-ca","key_type":"ecdsa-p256"}`

	// mTLS clients: operator (forbidden) and superadmin (allowed).
	op := newMTLSCertFixture(t, handler, "operator", "cert:issue")
	adm := newMTLSAdminFixture(t, handler, "cert:issue")
	sa := newMTLSCertFixture(t, handler, "SuperAdmin", "cert:issue")

	tests := []struct {
		name     string
		baseURL  string
		client   *http.Client
		auth     func(*http.Request)
		wantCode int
		wantErr  string // expected "code" field on error responses ("" => success)
	}{
		{
			name:    "password session without mTLS is hard-excluded from management mint",
			baseURL: srv.URL,
			client:  srv.Client(),
			auth: func(r *http.Request) {
				r.SetBasicAuth("admin", "admin")
			},
			wantCode: http.StatusUnauthorized,
			wantErr:  "api.auth_required",
		},
		{
			name:     "operator mTLS certificate cannot mint management profile",
			baseURL:  op.Server.URL,
			client:   op.Client,
			auth:     func(r *http.Request) {},
			wantCode: http.StatusForbidden,
			wantErr:  "api.management_mint_denied",
		},
		{
			name:     "admin mTLS certificate cannot mint management profile",
			baseURL:  adm.Server.URL,
			client:   adm.Client,
			auth:     func(r *http.Request) {},
			wantCode: http.StatusForbidden,
			wantErr:  "api.management_mint_denied",
		},
		{
			name:     "superadmin mTLS certificate mints management profile",
			baseURL:  sa.Server.URL,
			client:   sa.Client,
			auth:     func(r *http.Request) {},
			wantCode: http.StatusOK,
			wantErr:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, tt.baseURL+"/api/v1/certs", strings.NewReader(mintBody))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			tt.auth(req)
			resp, err := tt.client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			raw, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != tt.wantCode {
				t.Fatalf("status=%d want=%d body=%s", resp.StatusCode, tt.wantCode, string(raw))
			}
			if tt.wantErr != "" && !strings.Contains(string(raw), tt.wantErr) {
				t.Fatalf("missing error code %q in body=%s", tt.wantErr, string(raw))
			}
		})
	}
}
