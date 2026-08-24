package ca

import (
	"encoding/asn1"
	"testing"
)

func TestOIDRoot(t *testing.T) {
	root := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257}
	if !OIDIdentityExt.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1}) {
		t.Fatalf("OIDIdentityExt: expected 1.3.6.1.4.1.66257.1, got %v", OIDIdentityExt)
	}
	if !root.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257}) {
		t.Fatalf("root OID mismatch: expected 1.3.6.1.4.1.66257, got %v", root)
	}
}

func TestOIDAIC(t *testing.T) {
	if !OIDAIC.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1}) {
		t.Fatalf("OIDAIC: expected 1.3.6.1.4.1.66257.1.1, got %v", OIDAIC)
	}
	if !OIDAICAgentIdentity.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1, 1}) {
		t.Fatalf("OIDAICAgentIdentity: expected 1.3.6.1.4.1.66257.1.1.1, got %v", OIDAICAgentIdentity)
	}
	if !OIDAICDelegationAuthorization.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1, 2}) {
		t.Fatalf("OIDAICDelegationAuthorization: expected 1.3.6.1.4.1.66257.1.1.2, got %v", OIDAICDelegationAuthorization)
	}
}

func TestOIDCertificationExt(t *testing.T) {
	if !OIDCertificationExt.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 3}) {
		t.Fatalf("OIDCertificationExt: expected 1.3.6.1.4.1.66257.3, got %v", OIDCertificationExt)
	}
}

func TestOIDMarketAccessId(t *testing.T) {
	if !OIDMarketAccessId.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 3, 1}) {
		t.Fatalf("OIDMarketAccessId: expected 1.3.6.1.4.1.66257.3.1, got %v", OIDMarketAccessId)
	}
}

func TestOIDTrustLevel(t *testing.T) {
	if !OIDTrustLevel.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 3, 2}) {
		t.Fatalf("OIDTrustLevel: expected 1.3.6.1.4.1.66257.3.2, got %v", OIDTrustLevel)
	}
}
