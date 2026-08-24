// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package tsa

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/varwof/pkcs7"
)

func randomSerial() int {
	b := make([]byte, 2)
	rand.Read(b)
	return int(time.Now().UnixNano()&0x7FFFFFFF) + int(b[0])<<24 + int(b[1])<<16
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

	// RFC 3161 §2.4.2: the timeStampToken MUST include the TSA's certificate.
	// Only include the signing cert to minimize response size.
	chain := cfg.Chain

	sdDER, err := pkcs7.BuildSignedData(OIDTSTInfo, tstInfoDER, cfg.SignerCert, cfg.SignerKey, chain)
	if err != nil {
		return BuildErrorResponse(4, fmt.Sprintf("sign: %v", err))
	}

	respDER, err := BuildGrantedResponse(tstInfoDER, sdDER)
	if err != nil {
		return BuildErrorResponse(4, fmt.Sprintf("build response: %v", err))
	}

	return respDER, nil
}
