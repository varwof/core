// TSA ASN.1 structures for RFC 3161 Time-Stamp Protocol.
//
// ⚠️ ASN.1 FREEZE: This package's ASN.1 structures are frozen.
// Bug fixes only — no new ASN.1 struct types, no new OIDs.
// See dev-docs/ASN1_DISCIPLINE.md.
package tsa

import (
	"crypto"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"crypto/x509/pkix"
)

var (
	OIDTSTInfo         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	OIDDigestSHA256    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDDigestSHA384    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDDigestSHA512    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	OIDEcdsaWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDEcdsaWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDEcdsaWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

var oidOCSPNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

type TimeStampReq struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []asn1.RawValue       `asn1:"optional,tag:0"`
}

type MessageImprint struct {
	HashAlgorithm AlgorithmIdentifier
	HashedMessage []byte
}

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type TimeStampResp struct {
	Status         PKIStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type PKIStatusInfo struct {
	Status       int
	StatusString []string `asn1:"optional"`
	FailInfo     int      `asn1:"optional"`
}

type Accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}

type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   int
	GenTime        asn1.RawValue
	Accuracy       Accuracy            `asn1:"optional"`
	Ordering       bool                `asn1:"optional,default:false"`
	Nonce          *big.Int            `asn1:"optional"`
	TSA            asn1.RawValue       `asn1:"optional,tag:0"`
	TSTInfoExt     []asn1.RawValue     `asn1:"optional,tag:3"`
}

type TSTInfoConfig struct {
	Policy          asn1.ObjectIdentifier
	Ordering        bool
	AccuracySeconds int
	AccuracyMillis  int
	AccuracyMicros  int
	TSAGenName      asn1.RawValue
}

var OIDTSAPolicyDefault = asn1.ObjectIdentifier{0, 0}

func parseHashOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(OIDDigestSHA256):
		return crypto.SHA256, nil
	case oid.Equal(OIDDigestSHA384):
		return crypto.SHA384, nil
	case oid.Equal(OIDDigestSHA512):
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm: %v", oid)
	}
}

func ParseTimeStampReq(reqDER []byte) (*TimeStampReq, error) {
	var req TimeStampReq
	if _, err := asn1.Unmarshal(reqDER, &req); err != nil {
		return nil, fmt.Errorf("parse TimeStampReq: %w", err)
	}
	if req.Version != 1 {
		return nil, fmt.Errorf("unsupported TSA version: %d", req.Version)
	}
	return &req, nil
}

func BuildTSTInfo(req *TimeStampReq, serial int, cfg *TSTInfoConfig) ([]byte, int, error) {
	hash, err := parseHashOID(req.MessageImprint.HashAlgorithm.Algorithm)
	if err != nil {
		return nil, 2, err
	}

	expectedLen := hash.Size()
	if len(req.MessageImprint.HashedMessage) != expectedLen {
		return nil, 2, fmt.Errorf("bad digest length: got %d, want %d for %v",
			len(req.MessageImprint.HashedMessage), expectedLen, req.MessageImprint.HashAlgorithm.Algorithm)
	}

	for _, rawExt := range req.Extensions {
		var ext pkix.Extension
		if _, restErr := asn1.Unmarshal(rawExt.FullBytes, &ext); restErr == nil && ext.Critical {
			if !ext.Id.Equal(oidOCSPNonce) {
				return nil, 2, fmt.Errorf("unrecognized critical extension: %v", ext.Id)
			}
		}
	}

	timeStr := time.Now().UTC().Format("20060102150405Z")
	var nonce *big.Int
	if req.Nonce != nil {
		nonce = req.Nonce
	}

	policy := cfg.Policy
	if policy == nil {
		policy = OIDTSAPolicyDefault
	}

	info := TSTInfo{
		Version:        1,
		Policy:         policy,
		MessageImprint: req.MessageImprint,
		SerialNumber:   serial,
		GenTime: asn1.RawValue{
			Class: 0, Tag: asn1.TagGeneralizedTime,
			Bytes: []byte(timeStr),
		},
		Accuracy: Accuracy{
			Seconds: cfg.AccuracySeconds,
			Millis:  cfg.AccuracyMillis,
			Micros:  cfg.AccuracyMicros,
		},
		Ordering: cfg.Ordering,
		Nonce:    nonce,
		TSA:      cfg.TSAGenName,
	}
	der, err := asn1.Marshal(info)
	if err != nil {
		return nil, 4, fmt.Errorf("marshal TSTInfo: %w", err)
	}

	return der, 0, nil
}

func BuildGrantedResponse(tstInfoDER, contentInfoDER []byte) ([]byte, error) {
	statusDER, err := asn1.Marshal(PKIStatusInfo{Status: 0})
	if err != nil {
		return nil, fmt.Errorf("marshal status: %w", err)
	}

	// TimeStampResp ::= SEQUENCE { PKIStatusInfo, TimeStampToken OPTIONAL }
	// TimeStampToken ::= ContentInfo — directly the SEQUENCE, no tag wrapper.
	// ASN.1 decoders distinguish the two SEQUENCEs by context.
	inner := append(statusDER, contentInfoDER...)
	return asn1.Marshal(asn1.RawValue{
		Class: 0, Tag: asn1.TagSequence, IsCompound: true, Bytes: inner,
	})
}

func BuildErrorResponse(status int, msg string) ([]byte, error) {
	resp := TimeStampResp{
		Status: PKIStatusInfo{
			Status:       status,
			StatusString: []string{msg},
		},
	}
	return asn1.Marshal(resp)
}

func SerialFromBigInt(n *big.Int) int {
	return int(n.Int64())
}

func BuildTimeStampReq(hash crypto.Hash, digest []byte, nonce *big.Int) ([]byte, error) {
	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{
				Algorithm:  hashOID(hash),
				Parameters: asn1.RawValue{Class: 0, Tag: 5},
			},
			HashedMessage: digest,
		},
		CertReq: true,
	}
	if nonce != nil {
		req.Nonce = nonce
	}
	return asn1.Marshal(req)
}

func hashOID(h crypto.Hash) asn1.ObjectIdentifier {
	switch h {
	case crypto.SHA384:
		return OIDDigestSHA384
	case crypto.SHA512:
		return OIDDigestSHA512
	default:
		return OIDDigestSHA256
	}
}
