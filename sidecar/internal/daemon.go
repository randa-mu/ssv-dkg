package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"github.com/randa-mu/ssv-dkg/sidecar/internal/util"
	"io"
	"net/http"
)

type Daemon struct {
	port   uint
	router chi.Router
	key    crypto.Keypair
}

func NewDaemon(port uint, keyPath string) (Daemon, error) {
	if port == 0 {
		return Daemon{}, errors.New("you must provide a port")
	}

	if keyPath == "" {
		return Daemon{}, errors.New("you must pass a valid path to a keypair")
	}

	keypair, err := util.LoadKeypair(fmt.Sprintf("%s/keypair.json", keyPath))

	if err != nil {
		return Daemon{}, fmt.Errorf("error loading keypair: %v", err)
	}

	fmt.Println(fmt.Sprintf("Keypair loaded from %s", keyPath))

	router := chi.NewMux()
	router.Get("/health", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})

	router.Post("/sign", func(writer http.ResponseWriter, request *http.Request) {
		bytes, err := io.ReadAll(request.Body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		var requestBody api.SignRequest
		err = json.Unmarshal(bytes, &requestBody)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		signature, err := keypair.Sign(requestBody.Data)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		response := api.SignResponse{
			Signature: signature,
		}

		j, err := json.Marshal(response)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, err = writer.Write(j)
		if err != nil {
			fmt.Println("there was an error writing an HTTP response body")
		}
	})

	return Daemon{
		port:   port,
		router: router,
		key:    keypair,
	}, nil
}

func (d Daemon) Start() chan error {
	errs := make(chan error, 1)
	go func() {
		err := http.ListenAndServe(fmt.Sprintf(":%d", d.port), d.router)
		errs <- err
	}()
	return errs
}
