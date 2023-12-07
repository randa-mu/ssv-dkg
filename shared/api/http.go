package api

type SignResponse struct {
	EncryptedShare                 []byte
	SharePK                        []byte
	ValidatorPK                    []byte
	DepositDataPartialSignature    []byte
	DepositValidatorNonceSignature []byte
}

var SsvHealthPath = "/health"
var SsvIdentityPath = "/identity"

type SsvIdentityResponse struct {
	PublicKey []byte `json:"publicKey"`
	Nonce     uint64 `json:"nonce"`
}
