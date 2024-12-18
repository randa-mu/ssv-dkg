package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"golang.org/x/exp/slog"
)

type Ssv interface {
	Health() error
	Identity() (SsvIdentityResponse, error)
}

// BindSSVApi is used for stubbing a node API
func BindSSVApi(router *chi.Mux, node Ssv) {
	router.Get(SsvHealthPath, createSsvHealthAPI(node))
	router.Get(SsvIdentityPath, createSsvIdentityAPI(node))
}

func createSsvIdentityAPI(node Ssv) http.HandlerFunc {
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
			slog.Error("there was an error writing an HTTP Response body", "err", err)
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
