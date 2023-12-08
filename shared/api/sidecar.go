package api

import (
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"golang.org/x/exp/slog"
	"io"
	"net/http"
)

type Sidecar interface {
	Health() error
	Sign(request SignRequest) (SignResponse, error)
	Identity() (SidecarIdentityResponse, error)
	BroadcastDKG(packet SidecarDKGPacket) error
}

type SignRequest struct {
	Data      []byte `json:"data"`
	Operators []crypto.Identity
	SessionID []byte `json:"sessionId"`
}

type SidecarIdentityRequest struct {
	Address string `json:"address"`
}

type SidecarIdentityResponse struct {
	PublicKey []byte `json:"data"`
	Address   string `json:"address"`
	Signature []byte `json:"signature"`
}

var SidecarSignPath = "/sign"
var SidecarHealthPath = "/health"
var SidecarIdentityPath = "/identity"
var SidecarDKGPath = "/dkg"

func BindSidecarAPI(router *chi.Mux, node Sidecar) {
	router.Get(SidecarHealthPath, createHealthAPI(node))
	router.Post(SidecarSignPath, createSignAPI(node))
	router.Get(SidecarIdentityPath, createSidecarIdentityAPI(node))
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
