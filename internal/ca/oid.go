// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import "encoding/asn1"

// Varwof PKI OID tree (spec v1.5 §2.2):
//
// 1.3.6.1.4.1.66257 (IANA PEN — Varwof PKI)
// ├── 1  Identity and Permission Core
// │   ├── 1  AIC
// │   │   ├── 1  AgentIdentity (reserved)
// │   │   ├── 2  DelegationAuthorization
// │   ├── 2  PrincipalAuthorization
// │   ├── 3  Capability Scheme Registry (reserved)
// │   ├── 4  Vendor Extension Registry (reserved)
// │   └── 6  RenewalToken
// ├── 3  National/Industry Certification
// │   ├── 1  MarketAccessId
// │   ├── 2  TrustLevel
// │   ├── 3  CrossBorder (reserved)
// │   └── 4  EUDIWallet (reserved)
// ├── 5  GM (Chinese National Cryptography)
// └── 6  Certificate Transparency

// IANA-assigned PEN: 66257, OID root: 1.3.6.1.4.1.66257
var (
	// ── 1.x Identity and Permission Extensions ──
	OIDIdentityExt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1}

	// 1.1 AIC (core patent: AIC + natural person binding + capability protocolization)
	OIDAIC              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1}
	OIDAICAgentIdentity = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1, 1}
	// DelegationAuthorization (.1.1.2, principal signature evidence; pre-v1.5 old name UserAuth).
	OIDAICDelegationAuthorization = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1, 2}
	// DelegationDepthControl (.1.1.4, spec v1.7.2 §3.7, FUTURE delegation depth control).
	OIDDelegationDepthControl = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1, 4}
	OIDDDCChainDepth          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1, 4, 1}
	OIDDDCMaxDepth            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 1, 4, 2}

	// (1.1.5 and 1.1.9 removed in v1.5 — use Vendor Extension Registry 1.4 instead)

	// 1.2 PrincipalAuthorization (v1.5: replaces old UserPermission)
	OIDPrincipalAuthorization = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 2}

	// 1.3 Capability Scheme Registry (reserved)
	OIDCapabilitySchemeRegistry = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 3}

	// 1.4 Vendor Extension Registry (reserved)
	OIDVendorExtensionRegistry = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 4}

	// 1.6 RenewalToken (auto-renewal token, I-D §6)
	OIDRenewalToken = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 1, 6}

	// ── 3.x National/Industry Certification Extensions ──
	OIDCertificationExt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 3}

	// 3.1 MarketAccessId (complete credential, companion patent: national certification)
	OIDMarketAccessId = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 3, 1}

	// 3.2 TrustLevel
	OIDTrustLevel = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 3, 2}

	// 3.3 CrossBorder (reserved placeholder)
	OIDCrossBorder = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 3, 3}

	// ── 5.x GM (Chinese National Cryptography) Extensions ──
	OIDGM        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 5}
	OIDSM2Sig    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 5, 1}
	OIDSM3Hash   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 5, 2}
	OIDSM4Enc    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 5, 3}
	OIDSM2SM3Sig = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 5, 4}

	// ── 6.x Certificate Transparency Extensions ──
	OIDCT    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 6}
	OIDCTSCT = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 6, 1}
	OIDCTLog = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66257, 6, 2}
)
