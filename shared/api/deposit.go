package api

import (
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"github.com/randa-mu/ssv-dkg/shared/encoding"
)

type SignatureConfig struct {
	Operators   []string
	DepositData UnsignedDepositData
	Owner       OwnerConfig
	SsvClient   SsvClient
}

type OwnerConfig struct {
	Address        encoding.HexBytes `json:"address"`
	ValidatorNonce uint32            `json:"validator_nonce"`
}

type UnsignedDepositData struct {
	WithdrawalCredentials encoding.HexBytes `json:"withdrawal_credentials"`
	Amount                uint64            `json:"amount,omitempty"`
	ForkVersion           encoding.HexBytes `json:"fork_version,omitempty"`
	NetworkName           string            `json:"network_name,omitempty"`
	DepositCLIVersion     string            `json:"deposit_cli_version,omitempty"`
}

type SignedDepositData struct {
	PubKey                encoding.HexBytes `json:"pubkey"`
	WithdrawalCredentials encoding.HexBytes `json:"withdrawal_credentials"`
	Amount                uint64            `json:"amount,omitempty"`
	Signature             encoding.HexBytes `json:"signature"`
	DepositMessageRoot    encoding.HexBytes `json:"deposit_message_root,omitempty"`
	DepositDataRoot       encoding.HexBytes `json:"deposit_data_root"`
	ForkVersion           encoding.HexBytes `json:"fork_version,omitempty"`
	NetworkName           string            `json:"network_name,omitempty"`
	DepositCLIVersion     string            `json:"deposit_cli_version,omitempty"`
}

type SigningOutput struct {
	SessionID               encoding.UnpaddedBytes `json:"session_id"`
	GroupPublicPolynomial   encoding.UnpaddedBytes `json:"group_public_commitments"`
	OperatorShares          []OperatorShare        `json:"operator_shares"`
	DepositDataSignature    encoding.UnpaddedBytes `json:"deposit_data_signature"`
	ValidatorNonceSignature encoding.UnpaddedBytes `json:"validator_nonce_signature"`
}

type OperatorShare struct {
	Identity       crypto.Identity        `json:"identity"`
	EncryptedShare encoding.UnpaddedBytes `json:"encrypted_share"`
	SharePublicKey encoding.UnpaddedBytes `json:"share_public_key"`
}

type OperatorResponse struct {
	Identity     crypto.Identity
	SsvPublicKey []byte
	Response     SignResponse
}

func (u UnsignedDepositData) IntoMessage(groupPublicKey []byte) crypto.DepositMessage {
	return crypto.DepositMessage{
		WithdrawalCredentials: u.WithdrawalCredentials,
		Amount:                u.Amount,
		PublicKey:             groupPublicKey,
	}
}
