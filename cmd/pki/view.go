// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/engine/db"
)

func cmdViewCert(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("view", flag.ExitOnError)
	caName := fs.String("ca", "", bundle.T(curLang, "cli.flag_ca"))
	serial := fs.String("serial", "", "certificate serial number (hex)")
	format := fs.String("format", "table", "output format: table, json")
	fs.Parse(args)

	if *caName == "" || *serial == "" {
		return ef("cli.err_ca_and_serial_required")
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	rec, err := database.GetCert(*caName, *serial)
	if err != nil {
		return fmt.Errorf("get cert %s/%s: %w", *caName, *serial, err)
	}

	cert, err := x509.ParseCertificate(rec.CertDER)
	if err != nil {
		return fmt.Errorf("parse cert DER: %w", err)
	}

	if *format == "json" {
		return viewCertJSON(rec, cert)
	}
	viewCertTable(rec, cert)
	return nil
}

func viewCertTable(rec *db.CertRecord, cert *x509.Certificate) {
	fmt.Println("=== Certificate Record ===")
	fmt.Printf("Serial Number:    %s\n", rec.SerialNumber)
	fmt.Printf("CA Name:          %s\n", rec.CAName)
	fmt.Printf("Status:           %s", rec.Status)
	if rec.Status == "V" && rec.NotAfter.Before(time.Now()) {
		fmt.Printf(" (EXPIRED)")
	}
	fmt.Println()
	fmt.Printf("Profile:          %s\n", rec.Profile)
	fmt.Printf("Fingerprint:      %s\n", rec.Fingerprint)
	fmt.Printf("SPKI Hash:        %s\n", rec.SPKIHash)

	fmt.Println()
	fmt.Println("=== Subject ===")
	fmt.Printf("Subject DN:       %s\n", rec.Subject)
	fmt.Printf("Common Name:      %s\n", rec.CommonName)
	fmt.Printf("Organization:     %s\n", rec.SubjectO)
	fmt.Printf("Country:          %s\n", rec.SubjectC)

	fmt.Println()
	fmt.Println("=== Issuer ===")
	fmt.Printf("Issuer DN:        %s\n", rec.IssuerDN)

	fmt.Println()
	fmt.Println("=== Validity ===")
	fmt.Printf("Not Before:       %s\n", rec.NotBefore.Format(time.RFC3339))
	fmt.Printf("Not After:        %s\n", rec.NotAfter.Format(time.RFC3339))
	if rec.RevokedAt != nil {
		fmt.Printf("Revoked At:       %s\n", rec.RevokedAt.Format(time.RFC3339))
	}
	if rec.RevokeReason != nil {
		fmt.Printf("Revoke Reason:    %d\n", *rec.RevokeReason)
	}
	if rec.InvalidityDate != nil {
		fmt.Printf("Invalidity Date:  %s\n", rec.InvalidityDate.Format(time.RFC3339))
	}

	fmt.Println()
	fmt.Println("=== Key ===")
	fmt.Printf("Algorithm:        %s\n", rec.KeyAlgo)
	fmt.Printf("Key Size:         %d bits\n", rec.KeySize)
	fmt.Printf("Signature Algo:   %s\n", rec.SigAlgo)
	fmt.Printf("SKI:              %s\n", rec.SKI)
	fmt.Printf("AKI:              %s\n", rec.AKI)

	fmt.Println()
	fmt.Println("=== Extensions ===")
	fmt.Printf("SAN:              %s\n", rec.SAN)
	fmt.Printf("Is CA:            %v\n", cert.IsCA)
	fmt.Printf("Max Path Len:     %d\n", cert.MaxPathLen)
	fmt.Printf("Key Usage:        %s\n", formatKeyUsage(cert.KeyUsage))
	fmt.Printf("Ext Key Usage:    %s\n", formatExtKeyUsage(cert.ExtKeyUsage))
	if len(cert.UnknownExtKeyUsage) > 0 {
		fmt.Printf("Unknown EKU:      %s\n", formatOIDs(cert.UnknownExtKeyUsage))
	}
	if len(cert.DNSNames) > 0 {
		fmt.Printf("DNS Names:        %s\n", joinStrs(cert.DNSNames))
	}
	if len(cert.IPAddresses) > 0 {
		fmt.Printf("IP Addresses:     %s\n", joinIPs(cert.IPAddresses))
	}
	if len(cert.EmailAddresses) > 0 {
		fmt.Printf("Email Addresses:  %s\n", joinStrs(cert.EmailAddresses))
	}

	fmt.Println()
	fmt.Println("=== AIC Metadata ===")
	fmt.Printf("Principal UID:    %s\n", rec.PrincipalUid)
	fmt.Printf("Agent ID:         %s\n", rec.AgentId)

	fmt.Println()
	fmt.Println("=== Raw ===")
	fmt.Printf("Subject CN:       %s\n", cert.Subject.CommonName)
	fmt.Printf("Serial (hex):     %X\n", cert.SerialNumber)
	fmt.Printf("Serial (dec):     %s\n", cert.SerialNumber.String())
	fmt.Printf("Version:          %d\n", cert.Version+1)
	fmt.Printf("Signature Algo:   %s\n", cert.SignatureAlgorithm)
	fmt.Printf("Public Key Algo:  %s\n", cert.PublicKeyAlgorithm)
	if len(cert.Extensions) > 0 {
		fmt.Printf("Extensions:       %d total\n", len(cert.Extensions))
		for i, ext := range cert.Extensions {
			fmt.Printf("  [%d] %s (critical=%v, %d bytes)\n",
				i, ext.Id, ext.Critical, len(ext.Value))
		}
	}
	if len(cert.ExtraExtensions) > 0 {
		fmt.Printf("Extra Extensions: %d total\n", len(cert.ExtraExtensions))
		for i, ext := range cert.ExtraExtensions {
			fmt.Printf("  [%d] %s (critical=%v, %d bytes)\n",
				i, ext.Id, ext.Critical, len(ext.Value))
		}
	}
}

type certJSON struct {
	SerialNumber    string   `json:"serial_number"`
	CASerial        string   `json:"ca_serial_number,omitempty"`
	CAName          string   `json:"ca_name"`
	Status          string   `json:"status"`
	Profile         string   `json:"profile,omitempty"`
	Fingerprint     string   `json:"fingerprint"`
	SPKIHash        string   `json:"spki_hash,omitempty"`
	SubjectDN       string   `json:"subject_dn"`
	CommonName      string   `json:"common_name"`
	Organization    string   `json:"organization,omitempty"`
	Country         string   `json:"country,omitempty"`
	IssuerDN        string   `json:"issuer_dn"`
	NotBefore       string   `json:"not_before"`
	NotAfter        string   `json:"not_after"`
	RevokedAt       *string  `json:"revoked_at,omitempty"`
	RevokeReason    *int     `json:"revoke_reason,omitempty"`
	InvalidityDate  *string  `json:"invalidity_date,omitempty"`
	KeyAlgorithm    string   `json:"key_algorithm"`
	KeySize         int      `json:"key_size"`
	SignatureAlgo   string   `json:"signature_algorithm"`
	SKI             string   `json:"ski,omitempty"`
	AKI             string   `json:"aki,omitempty"`
	SAN             string   `json:"san,omitempty"`
	IsCA            bool     `json:"is_ca"`
	MaxPathLen      int      `json:"max_path_len"`
	KeyUsage        string   `json:"key_usage"`
	ExtKeyUsage     []string `json:"ext_key_usage"`
	DNSNames        []string `json:"dns_names,omitempty"`
	IPAddresses     []string `json:"ip_addresses,omitempty"`
	EmailAddresses  []string `json:"email_addresses,omitempty"`
	PrincipalUID    string   `json:"principal_uid,omitempty"`
	AgentID         string   `json:"agent_id,omitempty"`
	CertVersion     int      `json:"cert_version"`
	RawSerialDec    string   `json:"raw_serial_decimal"`
	ExtensionCount  int      `json:"extension_count"`
}

func viewCertJSON(rec *db.CertRecord, cert *x509.Certificate) error {
	j := certJSON{
		SerialNumber:   rec.SerialNumber,
		CAName:         rec.CAName,
		Status:         rec.Status,
		Profile:        rec.Profile,
		Fingerprint:    rec.Fingerprint,
		SPKIHash:       rec.SPKIHash,
		SubjectDN:      rec.Subject,
		CommonName:     rec.CommonName,
		Organization:   rec.SubjectO,
		Country:        rec.SubjectC,
		IssuerDN:       rec.IssuerDN,
		NotBefore:      rec.NotBefore.Format(time.RFC3339),
		NotAfter:       rec.NotAfter.Format(time.RFC3339),
		KeyAlgorithm:   rec.KeyAlgo,
		KeySize:        rec.KeySize,
		SignatureAlgo:  rec.SigAlgo,
		SKI:            rec.SKI,
		AKI:            rec.AKI,
		SAN:            rec.SAN,
		IsCA:           cert.IsCA,
		MaxPathLen:     cert.MaxPathLen,
		KeyUsage:       formatKeyUsage(cert.KeyUsage),
		ExtKeyUsage:    formatExtKeyUsage(cert.ExtKeyUsage),
		DNSNames:       cert.DNSNames,
		EmailAddresses: cert.EmailAddresses,
		PrincipalUID:   rec.PrincipalUid,
		AgentID:        rec.AgentId,
		CertVersion:    cert.Version + 1,
		RawSerialDec:   cert.SerialNumber.String(),
		ExtensionCount: len(cert.Extensions) + len(cert.ExtraExtensions),
	}
	if rec.RevokedAt != nil {
		s := rec.RevokedAt.Format(time.RFC3339)
		j.RevokedAt = &s
	}
	if rec.InvalidityDate != nil {
		s := rec.InvalidityDate.Format(time.RFC3339)
		j.InvalidityDate = &s
	}
	j.IPAddresses = make([]string, len(cert.IPAddresses))
	for i, ip := range cert.IPAddresses {
		j.IPAddresses[i] = ip.String()
	}
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func formatKeyUsage(u x509.KeyUsage) string {
	if u == 0 {
		return "none"
	}
	var names []string
	m := map[x509.KeyUsage]string{
		x509.KeyUsageDigitalSignature:  "DigitalSignature",
		x509.KeyUsageKeyEncipherment:   "KeyEncipherment",
		x509.KeyUsageDataEncipherment:  "DataEncipherment",
		x509.KeyUsageKeyAgreement:      "KeyAgreement",
		x509.KeyUsageCertSign:          "CertSign",
		x509.KeyUsageCRLSign:           "CRLSign",
		x509.KeyUsageEncipherOnly:      "EncipherOnly",
		x509.KeyUsageDecipherOnly:      "DecipherOnly",
	}
	for k, v := range m {
		if u&k != 0 {
			names = append(names, v)
		}
	}
	if len(names) == 0 {
		return fmt.Sprintf("0x%x", uint(u))
	}
	return joinStrs(names)
}

func formatExtKeyUsage(us []x509.ExtKeyUsage) []string {
	out := make([]string, 0, len(us))
	for _, u := range us {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			out = append(out, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			out = append(out, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			out = append(out, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			out = append(out, "EmailProtection")
		case x509.ExtKeyUsageIPSECEndSystem:
			out = append(out, "IPSECEndSystem")
		case x509.ExtKeyUsageIPSECTunnel:
			out = append(out, "IPSECTunnel")
		case x509.ExtKeyUsageIPSECUser:
			out = append(out, "IPSECUser")
		case x509.ExtKeyUsageTimeStamping:
			out = append(out, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			out = append(out, "OCSPSigning")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			out = append(out, "MicrosoftServerGatedCrypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			out = append(out, "MicrosoftCommercialCodeSigning")
		case x509.ExtKeyUsageAny:
			out = append(out, "Any")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			out = append(out, "MicrosoftKernelCodeSigning")
		default:
			out = append(out, fmt.Sprintf("Unknown(%d)", int(u)))
		}
	}
	return out
}

func formatOIDs(oids []asn1.ObjectIdentifier) string {
	if len(oids) == 0 {
		return "none"
	}
	var strs []string
	for _, o := range oids {
		strs = append(strs, o.String())
	}
	return strings.Join(strs, ", ")
}

func joinStrs(ss []string) string {
	return strings.Join(ss, ", ")
}

func joinIPs(ips []net.IP) string {
	var strs []string
	for _, ip := range ips {
		strs = append(strs, ip.String())
	}
	return strings.Join(strs, ", ")
}
