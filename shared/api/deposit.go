package api

import (
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"github.com/randa-mu/ssv-dkg/shared/json"
)

type OwnerConfig struct {
	Address        json.HexBytes `json:"address"`
	ValidatorNonce uint32        `json:"validator_nonce"`
}

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
	SessionID               json.UnpaddedBytes `json:"session_id"`
	GroupPublicKey          json.UnpaddedBytes `json:"group_public_commitments"`
	OperatorShares          []OperatorShare    `json:"operator_shares"`
	DepositDataSignature    json.UnpaddedBytes `json:"deposit_data_signature"`
	ValidatorNonceSignature json.UnpaddedBytes `json:"validator_nonce_signature"`
}

type OperatorShare struct {
	Identity       crypto.Identity    `json:"identity"`
	EncryptedShare json.UnpaddedBytes `json:"encrypted_share"`
}

type OperatorResponse struct {
	Identity     crypto.Identity
	SsvPublicKey []byte
	Response     SignResponse
}

func (u UnsignedDepositData) ExtractRequired() crypto.RequiredDepositFields {
	return crypto.RequiredDepositFields{
		WithdrawalCredentials: u.WithdrawalCredentials,
		Amount:                u.Amount,
	}
}
