package api

import (
	"github.com/randa-mu/ssv-dkg/shared/crypto"
)

type UnsignedDepositData struct {
	WithdrawalCredentials []byte `json:"withdrawal_credentials"`
	DepositDataRoot       []byte `json:"deposit_data_root"`
	DepositMessageRoot    []byte `json:"deposit_message_root,omitempty"`
	Amount                uint64 `json:"amount,omitempty"`
	ForkVersion           string `json:"fork_version,omitempty"`
	NetworkName           string `json:"network_name,omitempty"`
	DepositCLIVersion     string `json:"deposit_cli_version,omitempty"`
}

type SignedDepositData struct {
	UnsignedDepositData
	PubKey    []byte `json:"pubkey"`
	Signature []byte `json:"signature"`
}

type SigningOutput struct {
	SessionID             []byte            `json:"session_id"`
	GroupSignature        []byte            `json:"group_signature"`
	PolynomialCommitments []byte            `json:"group_public_commitments"`
	OperatorShares        []OperatorShare   `json:"operator_shares"`
	DepositData           SignedDepositData `json:"deposit_data"`
}

type OperatorShare struct {
	Identity       crypto.Identity `json:"identity"`
	EncryptedShare []byte          `json:"encrypted_share"`
}

type OperatorResponse struct {
	Identity crypto.Identity
	Response SignResponse
}

func (u UnsignedDepositData) ExtractRequired() crypto.RequiredDepositFields {
	return crypto.RequiredDepositFields{
		WithdrawalCredentials: u.WithdrawalCredentials,
		Amount:                u.Amount,
	}
}
