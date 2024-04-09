package api

type SignResponse struct {
	// the key share encrypted with the validator's RSA key
	EncryptedShare []byte
	// the BLS12-381 public key for the group created during the DKG
	PublicPolynomial []byte
	// the BLS12-381 public key for the specific validator node
	NodePK []byte
	// a partial signature over the deposit data's SHA256 hash
	DepositDataPartialSignature []byte
	// a partial signature over the validator's nonce's SHA256 hash
	DepositValidatorNonceSignature []byte
}

var SsvHealthPath = "/health"
var SsvIdentityPath = "/identity"

type SsvIdentityResponse struct {
	PublicKey []byte `json:"publicKey"`
}
