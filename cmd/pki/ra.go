package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

func cmdRA(cfg *internal.Config, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: goca ra <submit|list|approve|reject|show>")
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "submit":
		return cmdRASubmit(cfg, rest)
	case "list":
		return cmdRAList(cfg, rest)
	case "approve":
		return cmdRAApprove(cfg, rest)
	case "reject":
		return cmdRAReject(cfg, rest)
	case "show":
		return cmdRAShow(cfg, rest)
	default:
		return fmt.Errorf("unknown ra subcommand: %s", sub)
	}
}

func cmdRASubmit(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("ra submit", flag.ExitOnError)
	csrPath := fs.String("csr", "", bundle.T(curLang, "cli.flag_csr"))
	cn := fs.String("cn", "", bundle.T(curLang, "cli.flag_cn"))
	san := fs.String("san", "", bundle.T(curLang, "cli.flag_san"))
	profileName := fs.String("profile", "", bundle.T(curLang, "cli.flag_profile"))
	caName := fs.String("ca", "", bundle.T(curLang, "cli.flag_ca"))
	approvals := fs.Int("approvals", 0, "required approvals")
	fs.Parse(args)

	if *csrPath == "" {
		return fmt.Errorf("--csr is required")
	}
	if *cn == "" {
		return fmt.Errorf("--cn is required")
	}
	if *caName == "" {
		*caName = cfg.Defaults.CA
	}
	if *profileName == "" {
		*profileName = cfg.Defaults.Profile
	}
	reqApprovals := *approvals
	if reqApprovals < 1 {
		reqApprovals = cfg.RA.RequiredApprovals
		if reqApprovals < 1 {
			reqApprovals = 1
		}
	}

	csrBytes, err := os.ReadFile(*csrPath)
	if err != nil {
		return fmt.Errorf("read CSR: %w", err)
	}

	parsed, err := ca.ParseCSR(csrBytes)
	if err != nil {
		return fmt.Errorf("parse CSR: %w", err)
	}
	if *cn == "" {
		*cn = parsed.Subject.CommonName
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	sanList := ""
	if *san != "" {
		sanList = *san
	}

	requester := os.Getenv("USER")
	if requester == "" {
		requester = "unknown"
	}

	id, err := ca.SubmitRequest(database, csrBytes, *cn, sanList, *profileName, *caName, requester, reqApprovals)
	if err != nil {
		return fmt.Errorf("submit: %w", err)
	}

	notifyEvent(cfg, database, "ra_request_submitted", *caName, "", *cn, fmt.Sprintf("request_id=%d", id))
	fmt.Printf("RA request submitted: id=%d cn=%s ca=%s profile=%s approvals=%d\n", id, *cn, *caName, *profileName, reqApprovals)
	return nil
}

func cmdRAList(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("ra list", flag.ExitOnError)
	status := fs.String("status", "", "filter by status")
	fs.Parse(args)

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	requests, err := database.ListRARequests(*status, 100, 0)
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}

	fmt.Printf("%-4s %-20s %-30s %-12s %-10s %-10s\n", "ID", "CN", "CA", "Status", "Approvals", "Requester")
	fmt.Println(strings.Repeat("-", 90))
	for _, r := range requests {
		reqCount, _ := database.GetRARequest(r.ID)
		appStr := fmt.Sprintf("%d/%d", reqCount.ApprovalCount, r.RequiredApprovals)
		fmt.Printf("%-4d %-20s %-30s %-12s %-10s %-10s\n", r.ID, r.CommonName, r.CAName, r.Status, appStr, r.Requester)
	}
	return nil
}

func cmdRAApprove(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("ra approve", flag.ExitOnError)
	id := fs.Int("id", 0, "request ID")
	comment := fs.String("comment", "", "approval comment")
	fs.Parse(args)

	if *id == 0 {
		return ef("cli.err_id_required")
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	approver := os.Getenv("USER")
	if approver == "" {
		approver = "unknown"
	}

	signFn := func(csrDER []byte, cn, profile, caName string) (string, []byte, error) {
		caInfo, ok := cfg.CAs[caName]
		if !ok {
			return "", nil, ef("cli.err_ca_not_found", caName)
		}
		issuerCert, issuerKey, err := ca.LoadSigner(caInfo.Cert, caInfo.Key)
		if err != nil {
			return "", nil, fmt.Errorf("load CA: %w", err)
		}
		signCfg := &ca.SignConfig{
			DB:               database,
			CAKey:            issuerKey,
			CACert:           issuerCert,
			CAName:           caName,
			Profile:          ca.Profile(profile),
			CommonName:       cn,
			Hash:             cfg.Defaults.Hash,
			CRLBaseURL:       cfg.CRL.CRLBaseURL,
			OCSPURL:          cfg.Defaults.OCSPURL,
			IssuerURL:        cfg.Defaults.IssuerURL,
			IssuerAltNames:   cfg.Defaults.IssuerAltNames,
			SubjectInfoAccess: cfg.Defaults.SubjectInfoAccess,
			PolicyOIDs:       cfg.Defaults.PolicyOIDs,
		PolicyMappings:       mustPolicyMappings(cfg.Defaults.PolicyMappings),
		RequireExplicitPolicy: cfg.Defaults.RequireExplicitPolicy,
		InhibitPolicyMapping:  cfg.Defaults.InhibitPolicyMapping,
		InhibitAnyPolicy:      cfg.Defaults.InhibitAnyPolicy,
			PolicyFile:       cfg.Policy,
		}
		csr, err := ca.ParseCSR(csrDER)
		if err != nil {
			return "", nil, fmt.Errorf("parse CSR: %w", err)
		}
		signCfg.SubjectPubKey = csr.PublicKey

		result, err := ca.Sign(signCfg)
		if err != nil {
			return "", nil, fmt.Errorf("sign: %w", err)
		}
		return result.SerialHex, result.CertDER, nil
	}

	approved, serial, err := ca.ProcessApproval(database, *id, approver, "approved", *comment, signFn)
	if err != nil {
		return fmt.Errorf("approve: %w", err)
	}

	if approved {
		notifyEvent(cfg, database, "ra_request_approved", "", serial, "", fmt.Sprintf("request_id=%d serial=%s", *id, serial))
		fmt.Printf("Approval threshold met: request %d -> issued, serial=%s\n", *id, serial)
	} else {
		req, _ := database.GetRARequest(*id)
		fmt.Printf("Approval recorded for request %d (approved %d/%d)\n", *id, req.ApprovalCount, req.RequiredApprovals)
	}
	return nil
}

func cmdRAReject(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("ra reject", flag.ExitOnError)
	id := fs.Int("id", 0, "request ID")
	reason := fs.String("reason", "", "rejection reason")
	fs.Parse(args)

	if *id == 0 {
		return ef("cli.err_id_required")
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	if err := ca.RejectRequest(database, *id, *reason); err != nil {
		return fmt.Errorf("reject: %w", err)
	}
	notifyEvent(cfg, database, "ra_request_rejected", "", "", "", fmt.Sprintf("request_id=%d", *id))
	fmt.Printf("Request %d rejected.\n", *id)
	return nil
}

func cmdRAShow(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("ra show", flag.ExitOnError)
	id := fs.Int("id", 0, "request ID")
	fs.Parse(args)

	if *id == 0 {
		return ef("cli.err_id_required")
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	req, err := database.GetRARequest(*id)
	if err != nil {
		return fmt.Errorf("get request: %w", err)
	}

	issuedSerial := ""
	if req.IssuedSerial != nil {
		issuedSerial = *req.IssuedSerial
	}
	issuedAt := ""
	if req.IssuedAt != nil {
		issuedAt = *req.IssuedAt
	}
	rejectReason := ""
	if req.RejectReason != nil {
		rejectReason = *req.RejectReason
	}

	fmt.Printf("ID:           %d\n", req.ID)
	fmt.Printf("Common Name:  %s\n", req.CommonName)
	fmt.Printf("SANs:         %s\n", req.SANList)
	fmt.Printf("Profile:      %s\n", req.Profile)
	fmt.Printf("CA:           %s\n", req.CAName)
	fmt.Printf("Status:       %s\n", req.Status)
	fmt.Printf("Requester:    %s\n", req.Requester)
	fmt.Printf("Requested At: %s\n", req.RequestedAt)
	fmt.Printf("Approvals:    %d/%d\n", req.ApprovalCount, req.RequiredApprovals)
	if issuedSerial != "" {
		fmt.Printf("Issued Serial: %s\n", issuedSerial)
	}
	if issuedAt != "" {
		fmt.Printf("Issued At:    %s\n", issuedAt)
	}
	if rejectReason != "" {
		fmt.Printf("Reject Reason: %s\n", rejectReason)
	}
	return nil
}


