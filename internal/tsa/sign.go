// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package tsa

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"fmt"

	"github.com/varwof/pkcs7"
)

func randomSerial() int64 {
	// RFC 3161 §2.4.2: serial numbers MUST be unique. Use 8 bytes of
	// crypto/rand for 63 bits of entropy to make cross-restart collisions
	// negligible (< 2^-32 per request under high throughput). The top bit is
	// cleared so the value is always a positive ASN.1 INTEGER (a negative
	// serial is invalid DER for this purpose), and the return type is int64 so
	// 32-bit platforms do not silently truncate the entropy to 32 bits.
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return int64(binary.BigEndian.Uint64(b) &^ (uint64(1) << 63))
}

type TSAConfig struct {
	SignerCert *x509.Certificate
	SignerKey  crypto.Signer
	Chain      []*x509.Certificate
	TSTInfo    *TSTInfoConfig
}

func SignRequest(reqDER []byte, cfg *TSAConfig) ([]byte, error) {
	req, err := ParseTimeStampReq(reqDER)
	if err != nil {
		return BuildErrorResponse(2, err.Error())
	}

	tsCfg := cfg.TSTInfo
	if tsCfg == nil {
		tsCfg = &TSTInfoConfig{}
	}

	tstInfoDER, status, err := BuildTSTInfo(req, randomSerial(), tsCfg)
	if err != nil {
		return BuildErrorResponse(status, err.Error())
	}

	// RFC 3161 §2.4.1: when the request's certReq is FALSE (the default), the
	// TimeStampToken MUST NOT include the TSA signing certificate in
	// SignedData.certificates; when TRUE it MUST. RFC 3161 §2.4.2 requires at
	// most the signing cert (the full chain is optional); we include only the
	// signing cert to minimize response size.
	chain := cfg.Chain

	var sdDER []byte
	if req.CertReq {
		sdDER, err = pkcs7.BuildSignedData(OIDTSTInfo, tstInfoDER, cfg.SignerCert, cfg.SignerKey, chain)
	} else {
		sdDER, err = pkcs7.BuildSignedDataWithoutCertificates(OIDTSTInfo, tstInfoDER, cfg.SignerCert, cfg.SignerKey, chain)
	}
	if err != nil {
		return BuildErrorResponse(2, fmt.Sprintf("sign: %v", err))
	}

	respDER, err := BuildGrantedResponse(tstInfoDER, sdDER)
	if err != nil {
		return BuildErrorResponse(2, fmt.Sprintf("build response: %v", err))
	}

	return respDER, nil
}
