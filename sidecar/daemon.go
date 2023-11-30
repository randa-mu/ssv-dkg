package sidecar

import (
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"github.com/randa-mu/ssv-dkg/sidecar/internal/util"
	"github.com/rs/zerolog/log"
	"net/http"
)

type Daemon struct {
	port             uint
	ssvClient        api.Ssv
	router           chi.Router
	key              crypto.Keypair
	thresholdScheme  crypto.SigningScheme
	encryptionScheme crypto.EncryptionScheme
}

func NewDaemon(port uint, ssvURL string, keyPath string) (Daemon, error) {
	if port == 0 {
		return Daemon{}, errors.New("you must provide a port")
	}

	if keyPath == "" {
		return Daemon{}, errors.New("you must pass a valid path to a keypair")
	}

	if ssvURL == "" {
		return Daemon{}, errors.New("you must pass the URL of the SSV node you wish to connect the sidecar to")
	}

	keypair, err := util.LoadKeypair(keyPath)

	if err != nil {
		return Daemon{}, fmt.Errorf("error loading keypair: %v", err)
	}

	log.Info().Msgf("Keypair loaded from %s", keyPath)

	daemon := Daemon{
		port:             port,
		key:              keypair,
		ssvClient:        api.NewSsvClient(ssvURL),
		thresholdScheme:  crypto.NewBLSSuite(),
		encryptionScheme: crypto.NewRSASuite(),
	}
	router := createAPI(daemon)
	daemon.router = router

	return daemon, nil
}

func (d Daemon) Start() chan error {
	errs := make(chan error, 1)

	err := d.ssvClient.Health()
	if err != nil {
		errs <- err
	}
	go func() {
		err := http.ListenAndServe(fmt.Sprintf(":%d", d.port), d.router)
		errs <- err
	}()

	return errs
}
