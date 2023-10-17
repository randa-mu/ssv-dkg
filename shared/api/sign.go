package api

type SignRequest struct {
	Data []byte `json:"data"`
}

type SignResponse struct {
	PublicKey []byte `json:"publicKey"`
	Signature []byte `json:"signature"`
}
