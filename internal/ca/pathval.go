// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/varwof/engine/db"
)

// ─────────────────────────────────────────────────────────────────────
// Path builder + policy validator
//
// C3: a self-contained certificate path building and verification engine
// that applies RFC 5280 §6.1 policy processing (Policy Mappings / Policy
// Constraints / Inhibit anyPolicy) on top of Go's crypto/x509 signature and
// validity checks. Go's x509.Verify terminates at a trust anchor and stops,
// so it cannot express bridge-CA cross-domain trust where policy mapping
// between domains must be honored. This engine fills that gap.
//
// Data sources are abstracted behind CertSource so the engine can run against
// the DB (production), a memory snapshot, or an in-memory list (tests).
// ─────────────────────────────────────────────────────────────────────

// CertSource supplies certificates for path building. Both *db.DB and a test
// stub implement it.
type CertSource interface {
	// FindCA returns every configured CA certificate (ca_meta) whose Subject
	// matches the given issuer, plus the trust anchors. Implementations may
	// return nil slices for either group.
	FindIssuerCandidates(issuerRaw string) ([]*x509.Certificate, error)
	// TrustAnchors returns the set of trusted root certificates.
	TrustAnchors() ([]*x509.Certificate, error)
}

// DBSource adapts *db.DB to CertSource.
type DBSource struct {
	DB *db.DB
}

func (s *DBSource) TrustAnchors() ([]*x509.Certificate, error) {
	if s == nil || s.DB == nil {
		return nil, nil
	}
	anchors, err := s.DB.ListTrustAnchors(&db.TrustAnchorFilter{Trusted: &[]bool{true}[0]})
	if err != nil {
		return nil, fmt.Errorf("list trust anchors: %w", err)
	}
	var out []*x509.Certificate
	for _, a := range anchors {
		c, err := x509.ParseCertificate(a.CertDER)
		if err != nil {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

func (s *DBSource) FindIssuerCandidates(issuerRaw string) ([]*x509.Certificate, error) {
	if s == nil || s.DB == nil {
		return nil, nil
	}
	metas, err := s.DB.ListCAMetas()
	if err != nil {
		return nil, fmt.Errorf("list CA metas: %w", err)
	}
	var out []*x509.Certificate
	for _, m := range metas {
		c, err := x509.ParseCertificate(m.CertDER)
		if err != nil {
			continue
		}
		if string(c.RawSubject) == issuerRaw {
			out = append(out, c)
		}
	}
	return out, nil
}

// StaticSource is an in-memory CertSource (test-friendly).
type StaticSource struct {
	CAs   []*x509.Certificate
	Roots []*x509.Certificate
}

func (s *StaticSource) FindIssuerCandidates(issuerRaw string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	// Trust anchors may also serve as the terminal issuer (root CA).
	for _, c := range s.Roots {
		if c != nil && string(c.RawSubject) == issuerRaw {
			out = append(out, c)
		}
	}
	for _, c := range s.CAs {
		if c != nil && string(c.RawSubject) == issuerRaw {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *StaticSource) TrustAnchors() ([]*x509.Certificate, error) {
	return s.Roots, nil
}

// PolicyDecision is the outcome of RFC 5280 §6.1 policy processing over a
// verified chain.
type PolicyDecision struct {
	// AcceptedUserPolicies is the non-empty intersection of the final policy
	// set and the requester's user-initial-policy-set. When the requester
	// accepted anyPolicy (empty user set), AcceptedUserPolicies lists the
	// valid policies actually matched.
	AcceptedUserPolicies []string
	// MappedPolicies lists the effective policy mappings applied along the
	// path (issuerDomainPolicy → subjectDomainPolicy at each mapping CA).
	MappedPolicies []PolicyMappingApplied
	// InhibitAnyPolicyHit is true when anyPolicy was suppressed by an
	// inhibitAnyPolicy constraint along the path.
	InhibitAnyPolicyHit bool
	// ExplicitPolicyRequired is true when a requireExplicitPolicy constraint
	// was in force at the leaf.
	ExplicitPolicyRequired bool
	// ValidPolicyTree describes, per depth, the valid policies at that
	// certificate. Depth 0 is the leaf.
	ValidPolicyTree []ValidPolicyNode
}

type ValidPolicyNode struct {
	Depth    int      `json:"depth"`
	Policies []string `json:"policies"`
}

type PolicyMappingApplied struct {
	Depth               int    `json:"depth"`
	IssuerDomainPolicy  string `json:"issuer_domain_policy"`
	SubjectDomainPolicy string `json:"subject_domain_policy"`
}

// PathVerificationResult is the full output of VerifyPath.
type PathVerificationResult struct {
	// Valid is true when every x509-level check (signature, validity, KU,
	// basic constraints) passed.
	Valid bool `json:"valid"`
	// Chain is the ordered path leaf → root (length ≥ 1).
	Chain []*x509.Certificate `json:"-"`
	// RootIsTrusted is true when the path terminates in a trust anchor.
	RootIsTrusted bool `json:"root_is_trusted"`
	// Policy is the policy-processing outcome (nil when Valid is false or no
	// policy processing was requested).
	Policy *PolicyDecision `json:"policy,omitempty"`
	// RejectReason describes why the path was rejected (empty when Valid).
	RejectReason string `json:"reject_reason,omitempty"`
}

// VerifyPathOptions controls path verification.
type VerifyPathOptions struct {
	// UserInitialPolicySet is the set of acceptable certificate policies.
	// An empty set means "any policy is acceptable" (RFC 5280 §6.1.1 empty
	// user-initial-policy-set).
	UserInitialPolicySet []string
	// PolicyOID strings are parsed once; pass the ASN.1 OIDs to avoid
	// re-parsing.
	UserInitialPolicyOIDs []asn1ObjectIdentifier
	// VerifyPolicy enables RFC 5280 §6.1 policy processing. When false, only
	// structural validation (signatures, validity, trust) is performed.
	VerifyPolicy bool
	// CurrentTime overrides the "now" used for validity checks (default: now).
	CurrentTime time.Time
	// MaxDepth bounds chain length to protect against certificate loops.
	// Default 16 (RFC 5280 recommends ≤ 8 for normal PKIs, but bridge CA
	// chains can be longer).
	MaxDepth int
}

// BuildChain builds a certificate path from leaf up to a trust anchor using
// the given source. It performs no trust/policy evaluation — only structural
// walks (issuer matching, cycle protection, depth bound). Returns the path
// leaf-first (chain[0]=leaf, chain[len-1]=root candidate) and whether the
// terminal cert is in the trust anchors.
func BuildChain(leaf *x509.Certificate, src CertSource, maxDepth int) ([]*x509.Certificate, bool, error) {
	if leaf == nil {
		return nil, false, fmt.Errorf("build chain: nil leaf")
	}
	if maxDepth <= 0 {
		maxDepth = 16
	}
	anchors, err := src.TrustAnchors()
	if err != nil {
		return nil, false, err
	}
	anchorSet := make(map[string]*x509.Certificate, len(anchors))
	for _, a := range anchors {
		anchorSet[string(a.Raw)] = a
	}

	path := []*x509.Certificate{leaf}
	seen := map[string]bool{string(leaf.Raw): true}
	current := leaf
	for depth := 0; depth < maxDepth; depth++ {
		// Self-issued = root (trust anchor) reached.
		if _, ok := anchorSet[string(current.Raw)]; ok {
			return path, true, nil
		}
		// Self-signed but not a trust anchor → terminate as untrusted.
		if bytesEqual(current.RawSubject, current.RawIssuer) {
			return path, false, nil
		}
		cands, err := src.FindIssuerCandidates(string(current.RawIssuer))
		if err != nil {
			return nil, false, err
		}
		var next *x509.Certificate
		for _, c := range cands {
			if c == nil || seen[string(c.Raw)] {
				continue
			}
			// Prefer trust anchors when available.
			if anchor, ok := anchorSet[string(c.Raw)]; ok {
				next = anchor
				break
			}
			next = c
		}
		if next == nil {
			return path, false, nil // issuer not found
		}
		seen[string(next.Raw)] = true
		path = append(path, next)
		current = next
	}
	return path, false, fmt.Errorf("build chain: max depth %d exceeded", maxDepth)
}

// VerifyPath verifies a pre-built path (or builds one when src is non-nil):
//  1. signature and validity on every hop (x509-level)
//  2. trust anchor termination
//  3. optional RFC 5280 §6.1 policy processing
//
// When src is nil and chain is provided, only signature/validity + policy
// checks are run (no trust-anchor check beyond the caller's responsibility).
func VerifyPath(chain []*x509.Certificate, src CertSource, opts VerifyPathOptions) (*PathVerificationResult, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("verify path: empty chain")
	}

	// Build when needed.
	if src != nil {
		built, trusted, err := BuildChain(chain[0], src, opts.MaxDepth)
		if err != nil {
			return nil, err
		}
		chain = built
		_ = trusted
	}

	res := &PathVerificationResult{Chain: chain}
	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}

	// Pass 1: structural checks leaf → root.
	for i, c := range chain {
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			res.RejectReason = fmt.Sprintf("certificate %d (CN=%s) outside validity window", i, c.Subject.CommonName)
			return res, nil
		}
		// RFC 5280 §4.1.1.2: a certificate containing an unrecognized critical
		// extension MUST be rejected. Go's ParseCertificate surfaces these in
		// UnhandledCriticalExtensions; refuse the whole path if any appear.
		if len(c.UnhandledCriticalExtensions) > 0 {
			res.RejectReason = fmt.Sprintf("certificate %d (CN=%s) carries unrecognized critical extension(s): %v",
				i, c.Subject.CommonName, c.UnhandledCriticalExtensions)
			return res, nil
		}
		if i+1 < len(chain) {
			parent := chain[i+1]
			if err := c.CheckSignatureFrom(parent); err != nil {
				res.RejectReason = fmt.Sprintf("signature from %s: %v", parent.Subject.CommonName, err)
				return res, nil
			}
			if !parent.IsCA {
				res.RejectReason = fmt.Sprintf("issuer %s is not a CA", parent.Subject.CommonName)
				return res, nil
			}
			// H6 fix: a CA that carries a KeyUsage extension MUST assert
			// keyCertSign to issue. Go's CheckSignatureFrom does not enforce
			// this, so a "cert-only" CA could otherwise sign subordinate
			// certificates.
			if parent.KeyUsage != 0 && parent.KeyUsage&x509.KeyUsageCertSign == 0 {
				res.RejectReason = fmt.Sprintf("issuer %s lacks keyCertSign key usage", parent.Subject.CommonName)
				return res, nil
			}
		}
		// RFC 5280 §4.2.1.10 / §6.1.4(g): a certificate's names must satisfy the
		// name constraints of EVERY CA above it in the path — not only the
		// immediate issuer. Excluded sets union and permitted sets intersect down
		// the path; checking each certificate against every ancestor's constraints
		// independently is equivalent (the leaf is accepted only when all
		// ancestors permit it and none exclude it).
		for j := i + 1; j < len(chain); j++ {
			if reason := checkNameConstraints(chain[j], c); reason != "" {
				res.RejectReason = fmt.Sprintf("name constraint violation (issuer %s): %s",
					chain[j].Subject.CommonName, reason)
				return res, nil
			}
		}
	}

	// H6 fix: RFC 5280 §4.2.1.9 path length constraint. For each CA in the
	// path (root → first intermediate above the leaf), the number of
	// intermediate CAs beneath it must not exceed its MaxPathLen. Without this
	// a pathlen:0 sub-CA could mint further CAs and the constraint would be
	// silently ignored (cross.go's bridge-CA restriction depended on it).
	for j := len(chain) - 1; j >= 1; j-- {
		caCert := chain[j]
		if !caCert.BasicConstraintsValid || caCert.MaxPathLen < 0 {
			continue // no constraint
		}
		intermediatesBelow := j - 1 // certs chain[1..j-1]; leaf (chain[0]) not counted
		if intermediatesBelow > caCert.MaxPathLen {
			res.RejectReason = fmt.Sprintf(
				"path length exceeded: CA %s allows at most %d subordinate CA(s), %d present",
				caCert.Subject.CommonName, caCert.MaxPathLen, intermediatesBelow)
			return res, nil
		}
	}

	res.Valid = true

	// Trust anchor determination.
	if src != nil {
		anchors, err := src.TrustAnchors()
		if err != nil {
			return nil, err
		}
		root := chain[len(chain)-1]
		for _, a := range anchors {
			if bytesEqual(a.Raw, root.Raw) {
				res.RootIsTrusted = true
				break
			}
		}
	} else {
		// Caller owns trust; self-signed terminal implies root.
		root := chain[len(chain)-1]
		res.RootIsTrusted = bytesEqual(root.RawSubject, root.RawIssuer)
	}

	if opts.VerifyPolicy {
		dec, err := EvaluatePolicy(chain, opts)
		if err != nil {
			return nil, err
		}
		res.Policy = dec
		if len(dec.AcceptedUserPolicies) == 0 {
			// Policy failure is reported via RejectReason (and the Policy
			// decision). res.Valid intentionally reflects only structural
			// x509 checks (signature/validity/KU/basic-constraints); callers
			// that enable VerifyPolicy must also consult RejectReason/Policy
			// before accepting — the CLI verifypath does so (H6).
			res.RejectReason = "no certificate policy accepted"
		}
	}

	return res, nil
}

// asn1ObjectIdentifier is a thin alias so callers can pass crypto/x509 OIDs
// without pulling in extra imports in tests. We accept both string and OID
// forms via the options.
type asn1ObjectIdentifier = x509.OID

// oidAnyPolicy is the anyPolicy OID (2.5.29.32.0).
var oidAnyPolicy = mustOID(2, 5, 29, 32, 0)

func mustOID(parts ...uint64) x509.OID {
	oid, err := x509.OIDFromInts(parts)
	if err != nil {
		panic(err)
	}
	return oid
}

// policySet is a set of policy OID strings (RFC 5280 valid_policy_set).
type policySet map[string]bool

// EvaluatePolicy performs RFC 5280 §6.1 policy processing over an already
// structurally-valid path (chain[0] = leaf, ascending). It returns the policy
// decision, or an error when the path is malformed.
//
// The walk implements, for each certificate depth i (leaf = 0):
//   - decrement anyPolicy/explicitPolicy/inhibitAnyPolicy counters
//   - apply policy mappings (2.5.29.33) of intermediate CAs
//   - intersect/accumulate the valid policy set
//   - honor requireExplicitPolicy, inhibitPolicyMapping, inhibitAnyPolicy
//
// The final valid policy set is intersected with the user-initial-policy-set
// (empty = accept any). A non-empty intersection means the policy is accepted.
func EvaluatePolicy(chain []*x509.Certificate, opts VerifyPathOptions) (*PolicyDecision, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("evaluate policy: empty chain")
	}
	leaf := chain[0]

	// Initialize counters (RFC 5280 §6.1.2). If not set (negative), they stay
	// disabled; otherwise decrement per hop (leaf processing doesn't decrement
	// — see 6.1.4 vs 6.1.5).
	explicitPolicy, inhibitPolicyMapping, inhibitAnyPolicy := counterState(leaf)
	// The counters in 6.1.2 are seeded at the leaf and decremented as we walk
	// UP to each successive certificate. Depth-based handling below.

	userSet := make(policySet, len(opts.UserInitialPolicyOIDs))
	acceptAny := false
	if len(opts.UserInitialPolicySet) > 0 {
		for _, p := range opts.UserInitialPolicySet {
			userSet[p] = true
		}
	}
	for _, o := range opts.UserInitialPolicyOIDs {
		userSet[o.String()] = true
	}
	if len(userSet) == 0 {
		acceptAny = true
	}

	// valid_policy_tree: per-depth policy sets. Start empty; leaf populates.
	tree := make(map[int]policySet)
	tree[0] = policySet{}

	// Seed the leaf with its own policy identifiers. If the leaf has none and
	// anyPolicy is accepted, treat it as anyPolicy.
	if len(leaf.Policies) > 0 {
		for _, p := range leaf.Policies {
			tree[0][p.String()] = true
		}
	} else if acceptAny {
		tree[0][oidAnyPolicy.String()] = true
	}

	// RFC 5280 walk: for each certificate from leaf (i=0) toward root.
	// Counters are decremented when processing each successive cert upward,
	// per 6.1.4 (initial) and 6.1.5 (i > 0).
	var inhibitAnyPolicyHit, explicitPolicyRequired bool
	for i := 0; i < len(chain); i++ {
		cert := chain[i]
		// Apply 6.1.4 for leaf / 6.1.5 for intermediates: decrement counters
		// as we move through certificates that carry constraints.
		if i > 0 {
			explicitPolicy, inhibitPolicyMapping, inhibitAnyPolicy =
				decrementCounters(explicitPolicy, inhibitPolicyMapping, inhibitAnyPolicy, cert)
			// RFC 5280 §6.1.5(i)(j): each certificate along the path may
			// tighten the running counters — take the minimum of the running
			// value and the value asserted by this certificate. Without this,
			// a constraint asserted by an intermediate/root (e.g. the CA
			// setting inhibitAnyPolicy=0 when issuing a subCA) would be
			// ignored unless the leaf also asserted one.
			e2, m2, a2 := counterState(cert)
			if e2 >= 0 && (explicitPolicy < 0 || e2 < explicitPolicy) {
				explicitPolicy = e2
			}
			if m2 >= 0 && (inhibitPolicyMapping < 0 || m2 < inhibitPolicyMapping) {
				inhibitPolicyMapping = m2
			}
			if a2 >= 0 && (inhibitAnyPolicy < 0 || a2 < inhibitAnyPolicy) {
				inhibitAnyPolicy = a2
			}
		}
		if explicitPolicy == 0 && i > 0 {
			explicitPolicyRequired = true
		}

		// Policy mappings at this (issuing) certificate: issuerDomainPolicy of
		// cert[i] maps to subjectDomainPolicy expected in cert[i-1]'s cert.
		// RFC 5280: the mapping is applied to the SUBJECT certificate's
		// policies as seen by the ISSUER. So for i >= 1, map cert[i].PolicyMappings.
		if i >= 1 && inhibitPolicyMapping != 0 {
			applyMappings(tree[i-1], cert.PolicyMappings, i-1)
		}
		if i >= 1 && inhibitPolicyMapping == 0 {
			// inhibitPolicyMapping reached zero: no further mappings allowed.
			// Mappings already applied stay; skip further.
		}

		// Populate tree[i] from the child's (i-1) policy set propagated up,
		// intersected with cert[i]'s own policies (unless anyPolicy or the
		// intermediate carries no policy at all, in which case the child
		// policies are inherited per RFC 5280 §6.1.5).
		if i > 0 {
			child := tree[i-1]
			tree[i] = policySet{}
			parentPolicies := certPolicySet(cert)
			hasAny := parentPolicies[oidAnyPolicy.String()]
			if len(parentPolicies) == 0 || hasAny {
				// No explicit policy on the intermediate → inherit everything
				// the child established (anyPolicy also passes through).
				for p := range child {
					if p != oidAnyPolicy.String() {
						tree[i][p] = true
					}
				}
			} else {
				for p := range child {
					if p == oidAnyPolicy.String() {
						continue
					}
					if parentPolicies[p] {
						tree[i][p] = true
					}
				}
			}
		}
		// RFC 5280 §6.1.5(d): when inhibitAnyPolicy reaches 0, suppress
		// anyPolicy from the valid policy tree at this and all subsequent depths.
		if i > 0 && inhibitAnyPolicy == 0 {
			delete(tree[i], oidAnyPolicy.String())
			inhibitAnyPolicyHit = true
		}
	}

	// Final policy set = tree at root depth (or leaf when path len 1).
	rootDepth := len(chain) - 1
	finalSet := tree[rootDepth]
	if finalSet == nil {
		finalSet = tree[0]
	}

	// Remove anyPolicy from the final set (it is not an accepted output policy
	// per RFC 5280 §6.1.6 — it merely allows matching).
	matched := policySet{}
	for p := range finalSet {
		if p == oidAnyPolicy.String() {
			continue
		}
		if acceptAny || userSet[p] {
			matched[p] = true
		}
	}

	dec := &PolicyDecision{
		InhibitAnyPolicyHit:   inhibitAnyPolicyHit,
		ExplicitPolicyRequired: explicitPolicyRequired,
	}
	for p := range matched {
		dec.AcceptedUserPolicies = append(dec.AcceptedUserPolicies, p)
	}
	// Deterministic ordering.
	dec.AcceptedUserPolicies = sortStrings(dec.AcceptedUserPolicies)

	// Rebuild the per-depth tree as output.
	for d := 0; d <= rootDepth; d++ {
		if node, ok := tree[d]; ok && len(node) > 0 {
			policies := make([]string, 0, len(node))
			for p := range node {
				policies = append(policies, p)
			}
			dec.ValidPolicyTree = append(dec.ValidPolicyTree, ValidPolicyNode{
				Depth:    d,
				Policies: sortStrings(policies),
			})
		}
	}
	return dec, nil
}

// counterState extracts the initial explicitPolicy / inhibitPolicyMapping /
// inhibitAnyPolicy counters from a certificate per RFC 5280 §6.1.2. Unset
// fields (negative, per x509's encoding of "not present") disable the counter.
func counterState(cert *x509.Certificate) (explicit, inhibitMapping, inhibitAny int) {
	explicit = cert.RequireExplicitPolicy
	if explicit == 0 && !cert.RequireExplicitPolicyZero {
		explicit = -1 // not set
	}
	inhibitMapping = cert.InhibitPolicyMapping
	if inhibitMapping == 0 && !cert.InhibitPolicyMappingZero {
		inhibitMapping = -1
	}
	inhibitAny = cert.InhibitAnyPolicy
	if inhibitAny == 0 && !cert.InhibitAnyPolicyZero {
		inhibitAny = -1
	}
	return explicit, inhibitMapping, inhibitAny
}

// decrementCounters reduces the active counters by one when the current
// certificate carries the corresponding constraint (RFC 5280 §6.1.5(a)).
func decrementCounters(explicit, inhibitMapping, inhibitAny int, cert *x509.Certificate) (int, int, int) {
	if explicit > 0 {
		explicit--
	}
	if inhibitMapping > 0 {
		inhibitMapping--
	}
	if inhibitAny > 0 {
		inhibitAny--
	}
	// A certificate may also (re)assert constraints explicitly at zero.
	if explicit == 0 && cert.RequireExplicitPolicyZero {
		// stays 0
	}
	return explicit, inhibitMapping, inhibitAny
}

// certPolicySet returns the set of certificate policy OIDs carried by cert,
// including anyPolicy when present.
func certPolicySet(cert *x509.Certificate) policySet {
	out := policySet{}
	for _, p := range cert.Policies {
		out[p.String()] = true
	}
	return out
}

// applyMappings rewrites the child policy set according to the issuer's
// policyMappings extension at the given depth (RFC 5280 §6.1.4/d).
func applyMappings(child policySet, mappings []x509.PolicyMapping, depth int) {
	if len(mappings) == 0 {
		return
	}
	for _, m := range mappings {
		issuer := m.IssuerDomainPolicy.String()
		subject := m.SubjectDomainPolicy.String()
		if child[issuer] {
			child[subject] = true
		}
	}
}

func sortStrings(in []string) []string {
	// insertion sort (small n)
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j] < in[j-1]; j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
	return in
}

// checkNameConstraints validates that every name in the child certificate is
// acceptable under the issuer's RFC 5280 §4.2.1.10 Name Constraints extension
// (H6 fix). It returns a non-empty reason string on violation, or "" when the
// child satisfies the constraints (or the issuer carries none).
//
// Semantics per RFC 5280 §4.2.1.10:
//   - permittedSubtrees: a name is valid only if it is within at least one
//     permitted subtree. Absent permitted subtrees of a type ⇒ any name of
//     that type is permitted.
//   - excludedSubtrees: a name is invalid if it is within any excluded
//     subtree (exclusion wins over permission).
//
// DNS/URI/email constraints use the RFC 5280 §7.2 domain matching rules
// (constraint "example.com" also matches "a.example.com"); IP constraints use
// CIDR network containment.
func checkNameConstraints(issuer, child *x509.Certificate) string {
	hasAny := len(issuer.PermittedDNSDomains) > 0 || len(issuer.ExcludedDNSDomains) > 0 ||
		len(issuer.PermittedIPRanges) > 0 || len(issuer.ExcludedIPRanges) > 0 ||
		len(issuer.PermittedEmailAddresses) > 0 || len(issuer.ExcludedEmailAddresses) > 0 ||
		len(issuer.PermittedURIDomains) > 0 || len(issuer.ExcludedURIDomains) > 0
	if !hasAny {
		return ""
	}

	// DNS names: SANs, plus the subject CN only when no SAN exists (matching
	// x509.Verify's legacy CN fallback).
	dnsNames := append([]string{}, child.DNSNames...)
	if len(child.DNSNames) == 0 && child.Subject.CommonName != "" {
		dnsNames = append(dnsNames, child.Subject.CommonName)
	}
	for _, dns := range dnsNames {
		if matched, reason := constraintViolation(dns, issuer.PermittedDNSDomains, issuer.ExcludedDNSDomains, dnsMatch, "DNS name"); reason != "" {
			return fmt.Sprintf("%s %q: %s", "DNS name", dns, reason)
		} else if !matched {
			return fmt.Sprintf("DNS name %q not in any permitted subtree", dns)
		}
	}

	// URI SANs (RFC 5280 §7.4): constraints apply to the host part. A leading
	// "." denotes a domain namespace (subdomains only, NOT the apex); a bare
	// constraint specifies an exact host. A URI whose host is an IP address is
	// rejected when URI constraints are present.
	for _, u := range child.URIs {
		host := u.Hostname()
		if host == "" {
			// M8 security fix: a hostless URI (e.g. urn:..., spiffe://) has no
			// authority to match. Previously it was silently skipped, allowing
			// such a SAN to bypass configured permitted URI domain constraints.
			if len(issuer.PermittedURIDomains) > 0 {
				return fmt.Sprintf("hostless URI %q not in any permitted URI domain subtree", u.String())
			}
			continue
		}
		matched, ipHost, reason := uriHostMatch(host, issuer.PermittedURIDomains, issuer.ExcludedURIDomains)
		if reason != "" {
			return fmt.Sprintf("URI host %q: %s", host, reason)
		}
		if ipHost {
			return fmt.Sprintf("URI host %q specified as an IP address under URI constraints", host)
		}
		if !matched {
			return fmt.Sprintf("URI host %q not in any permitted subtree", host)
		}
	}

	// Email SANs / subject email (RFC 5280 §7.5): an "@" constraint is an exact
	// mailbox; a bare host constraint matches only addresses AT that host (not
	// subdomains); a leading "." constraint matches any address in the domain
	// except the apex host.
	for _, em := range child.EmailAddresses {
		matched, reason := emailMatchName(em, issuer.PermittedEmailAddresses, issuer.ExcludedEmailAddresses)
		if reason != "" {
			return fmt.Sprintf("email %q: %s", em, reason)
		}
		if !matched {
			return fmt.Sprintf("email %q not in any permitted subtree", em)
		}
	}

	// IP SANs.
	for _, ip := range child.IPAddresses {
		for _, ex := range issuer.ExcludedIPRanges {
			if ex.Contains(ip) {
				return fmt.Sprintf("IP address %v excluded by constraint", ip)
			}
		}
		if len(issuer.PermittedIPRanges) == 0 {
			continue
		}
		inPermitted := false
		for _, p := range issuer.PermittedIPRanges {
			if p.Contains(ip) {
				inPermitted = true
				break
			}
		}
		if !inPermitted {
			return fmt.Sprintf("IP address %v not in any permitted subtree", ip)
		}
	}

	return ""
}

// constraintViolation checks a single name against permitted/excluded subtree
// lists. match returns true when name is within the constraint. It returns
// (false, "") when the name is permitted but not matched by any permitted
// subtree (caller rejects), (true, "") on permitted, and (_, reason) on an
// explicit exclusion violation.
func constraintViolation[T any](name T, permitted, excluded []T, match func(constraint, name T) bool, kind string) (bool, string) {
	for _, c := range excluded {
		if match(c, name) {
			return false, fmt.Sprintf("excluded by %s constraint", kind)
		}
	}
	if len(permitted) == 0 {
		return true, ""
	}
	for _, c := range permitted {
		if match(c, name) {
			return true, ""
		}
	}
	return false, ""
}

// dnsMatch implements RFC 5280 §7.2 DNS name matching: the constraint matches
// the name when the name equals the constraint or is a subdomain (left-label
// extension) of it (case-insensitive). A leading "." does not change the DNS
// result. This is correct for the dNSName name form only; URI hosts and email
// domains use different rules (see uriHostMatch / emailMatchName).
func dnsMatch(constraint, name string) bool {
	c := strings.ToLower(strings.TrimPrefix(constraint, "."))
	n := strings.ToLower(name)
	return n == c || strings.HasSuffix(n, "."+c)
}

// uriHostMatch applies RFC 5280 §7.4 URI-host name constraints. It returns
// (permitted, ipHost, reason). ipHost is true when URI constraints are present
// and the host is an IP address — RFC 5280 §7.4 requires rejecting such URIs.
func uriHostMatch(host string, permitted, excluded []string) (bool, bool, string) {
	constraintPresent := len(permitted) > 0 || len(excluded) > 0
	if net.ParseIP(host) != nil {
		return false, constraintPresent, ""
	}
	for _, c := range excluded {
		if uriHostIn(c, host) {
			return false, false, "excluded by URI host constraint"
		}
	}
	if len(permitted) == 0 {
		return true, false, ""
	}
	for _, c := range permitted {
		if uriHostIn(c, host) {
			return true, false, ""
		}
	}
	return false, false, ""
}

// uriHostIn reports whether host is within the URI-host constraint namespace
// per RFC 5280 §7.4: a leading "." matches only proper subdomains (never the
// apex); a bare constraint matches the exact host only.
func uriHostIn(constraint, host string) bool {
	c := strings.ToLower(constraint)
	h := strings.ToLower(host)
	if strings.HasPrefix(c, ".") {
		base := c[1:]
		return h != base && strings.HasSuffix(h, "."+base)
	}
	return h == c
}

// emailMatchName applies RFC 5280 §7.5 email name constraints to addr, against
// the permitted/excluded lists. Returns (permitted, reason) where reason is
// non-empty on an explicit exclusion violation.
func emailMatchName(addr string, permitted, excluded []string) (bool, string) {
	for _, c := range excluded {
		if emailAddrIn(c, addr) {
			return false, "excluded by email constraint"
		}
	}
	if len(permitted) == 0 {
		return true, ""
	}
	for _, c := range permitted {
		if emailAddrIn(c, addr) {
			return true, ""
		}
	}
	return false, ""
}

// emailAddrIn reports whether addr is within the email constraint namespace per
// RFC 5280 §7.5: an "@" constraint is an exact mailbox; a bare host constraint
// matches addresses AT that host only (not subdomains); a leading "." matches
// any address in the domain except the apex host.
func emailAddrIn(constraint, addr string) bool {
	c := strings.ToLower(constraint)
	a := strings.ToLower(addr)
	if strings.Contains(c, "@") {
		return c == a
	}
	at := strings.LastIndexByte(a, '@')
	if at < 0 {
		return false
	}
	domain := a[at+1:]
	if strings.HasPrefix(c, ".") {
		base := c[1:]
		return domain != base && strings.HasSuffix(domain, "."+base)
	}
	return domain == c
}
