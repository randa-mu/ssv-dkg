package api

import (
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
	"io"
	"net/http"
)

type Ssv interface {
	Health() error
	Identity() (SsvIdentityResponse, error)
}

func BindSSVApi(router *chi.Mux, node Ssv) {
	router.Get(SsvHealthPath, createSsvHealthAPI(node))
	router.Get(SsvIdentityPath, createIdentityAPI(node))
}

func createIdentityAPI(node Ssv) http.HandlerFunc {
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
			fmt.Println("there was an error writing an HTTP response body")
		}
	}
}

func createSsvHealthAPI(node Ssv) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		err := node.Health()
		if err != nil {
			writer.WriteHeader(http.StatusServiceUnavailable)
		}
		writer.WriteHeader(http.StatusOK)
	}
}

type Sidecar interface {
	Health() error
	Sign(request SignRequest) (SignResponse, error)
}

func BindSidecarAPI(router *chi.Mux, node Sidecar) {
	router.Get(SidecarHealthPath, createHealthAPI(node))
	router.Post(SidecarSignPath, createSignAPI(node))
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
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		j, err := json.Marshal(response)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, err = writer.Write(j)
		if err != nil {
			log.Error().Err(err).Msg("error writing a signing HTTP response")
		}
	}
}
