package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"golang.org/x/exp/slog"

	"github.com/randa-mu/ssv-dkg/shared/crypto"
)

type Sidecar interface {
	Health() error
	Sign(request SignRequest) (SignResponse, error)
	Reshare(request ReshareRequest) (ReshareResponse, error)
	Identity() (SidecarIdentityResponse, error)
	BroadcastDKG(packet SidecarDKGPacket) error
}

type SignRequest struct {
	SessionID   []byte              `json:"session_id"`
	DepositData UnsignedDepositData `json:"deposit_data"`
	OwnerConfig OwnerConfig         `json:"owner_config"`
	Operators   []crypto.Identity   `json:"operators"`
}

type SignResponse struct {
	// the key share encrypted with the validator's RSA key
	EncryptedShare []byte `json:"encrypted_share"`

	// the BLS12-381 public key for the group created during the DKG
	PublicPolynomial []byte `json:"public_polynomial"`

	// a partial signature over the deposit data's SHA256 hash
	DepositDataPartialSignature []byte `json:"deposit_data_partial_signature"`

	// a partial signature over the validator's nonce's SHA256 hash
	ValidatorNoncePartialSignature []byte `json:"validator_nonce_partial_signature"`
}

type ReshareRequest struct {
	Operators                  []crypto.Identity `json:"operators"`
	PreviousState              PreviousDKGState  `json:"previous_state"`
	PreviousEncryptedShareHash []byte            `json:"previous_encrypted_share_hash"`
}

type PreviousDKGState struct {
	SessionID                   string            `json:"session_id"`
	Nodes                       []crypto.Identity `json:"nodes"`
	PublicPolynomialCommitments []byte            `json:"public_polynomial_commitments"`
}

type ReshareResponse struct {
	// the new key share encrypted with the validator's RSA key
	EncryptedShare []byte `json:"encrypted_share"`

	// the BLS12-381 public key for the group created during the DKG
	// it should be the same as the initial sharing, but always good to check
	PublicPolynomial []byte `json:"public_polynomial"`
}

type SsvIdentityResponse struct {
	PublicKey []byte `json:"publicKey"`
}

type SidecarIdentityResponse struct {
	OperatorID uint32 `json:"operator_id"`
	PublicKey  []byte `json:"data"`
	Address    string `json:"address"`
	Signature  []byte `json:"signature"`
}

var (
	SidecarSignPath     = "/sign"
	SidecarResharePath  = "/reshare"
	SidecarHealthPath   = "/health"
	SidecarIdentityPath = "/identity"
	SidecarDKGPath      = "/dkg"
)

func BindSidecarAPI(router *chi.Mux, node Sidecar) {
	router.Get(SidecarHealthPath, createHealthAPI(node))
	router.Get(SidecarIdentityPath, createSidecarIdentityAPI(node))
	router.Post(SidecarSignPath, createSignAPI(node))
	router.Post(SidecarResharePath, createReshareAPI(node))
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
			slog.Debug("error reading signing body", "body", bytes, "err", err)
			return
		}

		var requestBody SignRequest
		err = json.Unmarshal(bytes, &requestBody)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			slog.Debug("error marshalling signing body", "body", bytes, "err", err)
			return
		}

		response, err := node.Sign(requestBody)
		if err != nil {
			slog.Error("error signing deposit data", "err", err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		j, err := json.Marshal(response)
		if err != nil {
			slog.Error("error marshalling signed deposit data", "err", err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, err = writer.Write(j)
		if err != nil {
			slog.Error("error writing a signing HTTP Response", "err", err)
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
			slog.Debug("error marshalling Response in resharing", "err", err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, err = writer.Write(j)
		if err != nil {
			slog.Error("error writing a reshare HTTP Response", "err", err)
		}
	}
}

func createSidecarIdentityAPI(node Sidecar) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		identity, err := node.Identity()
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
			slog.Error("error writing an Identity HTTP Response", "err", err)
		}
	}
}

func createSidecarDKGAPI(node Sidecar) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		requestBytes, err := io.ReadAll(request.Body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			slog.Error("error reading DKG packet", "err", err)
			return
		}

		var dkgPacket SidecarDKGPacket
		err = json.Unmarshal(requestBytes, &dkgPacket)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			slog.Error("error unmarshalling DKG packet", "err", err)
			return
		}

		err = node.BroadcastDKG(dkgPacket)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			slog.Error("error broadcasting DKG packet", "err", err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}
}
