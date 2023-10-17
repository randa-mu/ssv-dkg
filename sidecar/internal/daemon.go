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
	suite  crypto.Suite
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

	suite := crypto.NewBLSSuite()

	daemon := Daemon{
		port:  port,
		key:   keypair,
		suite: suite,
	}
	router := createAPI(daemon)
	daemon.router = router

	return daemon, nil
}

func (d Daemon) Start() chan error {
	errs := make(chan error, 1)
	go func() {
		err := http.ListenAndServe(fmt.Sprintf(":%d", d.port), d.router)
		errs <- err
	}()
	return errs
}

func createAPI(d Daemon) *chi.Mux {
	router := chi.NewMux()

	router.Get("/health", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})

	router.Post("/sign", func(writer http.ResponseWriter, request *http.Request) {
		fmt.Println("Received signing request")
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

		signature, err := d.suite.Sign(d.key, requestBody.Data)
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}

		response := api.SignResponse{
			Signature: signature,
			PublicKey: d.key.Public,
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

	return router
}
