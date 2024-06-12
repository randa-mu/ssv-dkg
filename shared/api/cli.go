package api

import (
	"fmt"
	"math/big"

	"github.com/randa-mu/ssv-dkg/shared/crypto"
)

type UnsignedDepositData struct {
	WithdrawalCredentials []byte `json:"withdrawal_credentials"`
	DepositDataRoot       []byte `json:"deposit_data_root"`
	DepositMessageRoot    []byte `json:"deposit_message_root,omitempty"`
	Amount                BigInt `json:"amount,omitempty"`
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

type BigInt struct {
	big.Int
}

// MarshalJSON intentionally uses a value pointer or things go wrong
func (b BigInt) MarshalJSON() ([]byte, error) {
	return []byte(b.String()), nil
}

func (b *BigInt) UnmarshalJSON(p []byte) error {
	if string(p) == "null" {
		return nil
	}
	var z big.Int
	_, ok := z.SetString(string(p), 10)
	if !ok {
		return fmt.Errorf("not a valid big integer: %s", p)
	}
	b.Int = z
	return nil
}
