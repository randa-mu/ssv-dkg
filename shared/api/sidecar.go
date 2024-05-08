package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"golang.org/x/exp/slog"
)

type Sidecar interface {
	Health() error
	Sign(request SignRequest) (SignResponse, error)
	Reshare(request ReshareRequest) (ReshareResponse, error)
	Identity(request SidecarIdentityRequest) (SidecarIdentityResponse, error)
	BroadcastDKG(packet SidecarDKGPacket) error
}

type SignRequest struct {
	SessionID      []byte            `json:"session_id"`
	ValidatorNonce uint32            `json:"validator_nonce"`
	Data           []byte            `json:"data"`
	Operators      []crypto.Identity `json:"operators"`
}

type SignResponse struct {
	// the key share encrypted with the validator's RSA key
	EncryptedShare []byte `json:"encrypted_share"`

	// the BLS12-381 public key for the group created during the DKG
	PublicPolynomial []byte `json:"public_polynomial"`

	// the BLS12-381 public key for the specific validator node
	NodePK []byte `json:"node_pk"`

	// a partial signature over the deposit data's SHA256 hash
	DepositDataPartialSignature []byte `json:"deposit_data_partial_signature"`

	// a partial signature over the validator's nonce's SHA256 hash
	DepositValidatorNonceSignature []byte `json:"deposit_validator_nonce_signature"`
}

type ReshareRequest struct {
	SessionID      []byte            `json:"session_id"`
	ValidatorNonce uint32            `json:"validator_nonce"`
	Operators      []crypto.Identity `json:"operators"`
}

type ReshareResponse struct {
	// the new key share encrypted with the validator's RSA key
	EncryptedShare []byte `json:"encrypted_share"`

	// the BLS12-381 public key for the group created during the DKG
	// it should be the same as the initial sharing, but always good to check
	PublicPolynomial []byte `json:"public_polynomial"`

	// the BLS12-381 public key for the specific validator node
	NodePK []byte `json:"node_pk"`
}

var SsvHealthPath = "/health"
var SsvIdentityPath = "/identity"

type SsvIdentityResponse struct {
	PublicKey []byte `json:"publicKey"`
}

type SidecarIdentityRequest struct {
	ValidatorNonce uint32 `json:"validator_nonce"`
}

type SidecarIdentityResponse struct {
	PublicKey []byte `json:"data"`
	Address   string `json:"address"`
	Signature []byte `json:"signature"`
}

var SidecarSignPath = "/sign"
var SidecarResharePath = "/reshare"
var SidecarHealthPath = "/health"
var SidecarIdentityPath = "/identity"
var SidecarDKGPath = "/dkg"

func BindSidecarAPI(router *chi.Mux, node Sidecar) {
	router.Get(SidecarHealthPath, createHealthAPI(node))
	router.Post(SidecarSignPath, createSignAPI(node))
	router.Post(SidecarResharePath, createReshareAPI(node))
	router.Post(SidecarIdentityPath, createSidecarIdentityAPI(node))
	router.Post(SidecarDKGPath, createSidecarDKGAPI(node))
}

func createHealthAPI(node Sidecar) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		err := node.Health()
		if err != nil {
			writer.WriteHeader(http.StatusServiceUnavailable)
		}
		writer.WriteHeader(http.StatusOK)
	}
}

func createSignAPI(node Sidecar) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		bytes, err := io.ReadAll(request.Body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		var requestBody SignRequest
		err = json.Unmarshal(bytes, &requestBody)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		response, err := node.Sign(requestBody)
		if err != nil {
			slog.Error("error signing deposit data", err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		j, err := json.Marshal(response)
		if err != nil {
			slog.Error("error marshalling signed deposit data", err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, err = writer.Write(j)
		if err != nil {
			slog.Error("error writing a signing HTTP response", err)
		}
	}
}

func createReshareAPI(node Sidecar) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		bytes, err := io.ReadAll(request.Body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		var requestBody ReshareRequest
		err = json.Unmarshal(bytes, &requestBody)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		reshareResponse, err := node.Reshare(requestBody)
		if err != nil {
			slog.Debug("error resharing", "err", err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		j, err := json.Marshal(reshareResponse)
		if err != nil {
			slog.Debug("error marshalling response in resharing", "err", err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, err = writer.Write(j)
		if err != nil {
			slog.Error("error writing a reshare HTTP response", err)
		}
	}
}

func createSidecarIdentityAPI(node Sidecar) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		bytes, err := io.ReadAll(request.Body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		var requestBody SidecarIdentityRequest
		err = json.Unmarshal(bytes, &requestBody)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		identity, err := node.Identity(requestBody)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		j, err := json.Marshal(identity)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, err = writer.Write(j)
		if err != nil {
			slog.Error("error writing an identity HTTP response", err)
		}
	}
}

func createSidecarDKGAPI(node Sidecar) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		requestBytes, err := io.ReadAll(request.Body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			slog.Error("error reading DKG packet", err)
			return
		}

		var dkgPacket SidecarDKGPacket
		err = json.Unmarshal(requestBytes, &dkgPacket)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			slog.Error("error unmarshalling DKG packet", err)
			return
		}

		err = node.BroadcastDKG(dkgPacket)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			slog.Error("error broadcasting DKG packet", err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}

}
