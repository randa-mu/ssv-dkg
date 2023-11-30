package api

var SidecarSignPath = "/sign"
var SidecarHealthPath = "/health"

type SignRequest struct {
	Data []byte `json:"data"`
}

type SignResponse struct {
	EncryptedShare                 []byte `ssz-max:"2048"`
	SharePK                        []byte `ssz-max:"2048"`
	ValidatorPK                    []byte `ssz-size:"48"`
	DepositDataPartialSignature    []byte `ssz-size:"96"`
	DepositValidatorNonceSignature []byte `ssz-size:"96"`
}

var SsvHealthPath = "/health"
var SsvIdentityPath = "/identity"

type SsvIdentityResponse struct {
	PublicKey []byte `json:"publicKey"`
	Nonce     uint64 `json:"nonce"`
}
