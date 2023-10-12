package api

type SignRequest struct {
	Data []byte `json:"data"`
}

type SignResponse struct {
	Signature []byte `json:"data"`
}
