package api

import (
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"golang.org/x/exp/slog"
	"net/http"
)

type Ssv interface {
	Health() error
	Identity() (SsvIdentityResponse, error)
}

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
			slog.Error("there was an error writing an HTTP response body", "err", err)
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
