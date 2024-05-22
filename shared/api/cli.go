package api

import "github.com/randa-mu/ssv-dkg/shared/crypto"

type SigningOutput struct {
	SessionID             []byte          `json:"session_id"`
	GroupSignature        []byte          `json:"group_signature"`
	PolynomialCommitments []byte          `json:"group_public_commitments"`
	OperatorShares        []OperatorShare `json:"operator_shares"`
}

type OperatorShare struct {
	Identity       crypto.Identity `json:"identity"`
	EncryptedShare []byte          `json:"encrypted_share"`
}

type OperatorResponse struct {
	Identity crypto.Identity
	Response SignResponse
}
