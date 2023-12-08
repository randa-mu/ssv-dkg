package sidecar

import (
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"github.com/randa-mu/ssv-dkg/sidecar/dkg"
	"github.com/randa-mu/ssv-dkg/sidecar/internal/util"
	"github.com/rs/zerolog/log"
	"net/http"
	"net/url"
)

type Daemon struct {
	port             uint
	publicURL        string
	ssvClient        api.Ssv
	router           chi.Router
	dkg              *dkg.DKGCoordinator
	key              crypto.Keypair
	thresholdScheme  crypto.ThresholdScheme
	encryptionScheme crypto.EncryptionScheme
}

func NewDaemon(port uint, publicURL string, ssvURL string, keyPath string) (Daemon, error) {
	if port == 0 {
		return Daemon{}, errors.New("you must provide a port")
	}

	if keyPath == "" {
		return Daemon{}, errors.New("you must pass a valid path to a keypair")
	}

	if ssvURL == "" {
		return Daemon{}, errors.New("you must pass the URL of the SSV node you wish to connect the sidecar to")
	}

	if publicURL == "" {
		return Daemon{}, errors.New("you must pass a public URL flag")
	}
	if _, err := url.Parse(publicURL); err != nil {
		return Daemon{}, errors.New("you must pass a public URL flag")
	}

	keypair, err := util.LoadKeypair(keyPath)

	if err != nil {
		return Daemon{}, fmt.Errorf("error loading keypair: %v", err)
	}

	log.Info().Msgf("Keypair loaded from %s", keyPath)

	thresholdScheme := crypto.NewBLSSuite()
	dkgCoordinator := dkg.NewDKGCoordinator(publicURL, thresholdScheme)
	daemon := Daemon{
		port:             port,
		key:              keypair,
		publicURL:        publicURL,
		ssvClient:        api.NewSsvClient(ssvURL),
		dkg:              &dkgCoordinator,
		thresholdScheme:  thresholdScheme,
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
