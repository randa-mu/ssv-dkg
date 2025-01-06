package sidecar

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"golang.org/x/exp/slog"

	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"github.com/randa-mu/ssv-dkg/sidecar/dkg"
	"github.com/randa-mu/ssv-dkg/sidecar/internal/util"
)

type Daemon struct {
	port             uint
	publicURL        string
	server           *http.Server
	dkg              DKGProtocol
	db               *dkg.FileStore
	key              crypto.Keypair
	ssvKey           []byte
	stateDir         string
	thresholdScheme  crypto.ThresholdScheme
	encryptionScheme crypto.EncryptionScheme
}

type DKGProtocol interface {
	RunDKG(identities []crypto.Identity, sessionID []byte, keypair crypto.Keypair) (*dkg.Output, error)
	RunReshare(identities []crypto.Identity, sessionID []byte, keypair crypto.Keypair, state dkg.GroupFile) (*dkg.Output, error)
	ProcessPacket(packet api.SidecarDKGPacket) error
}

func NewDaemon(port uint, publicURL string, stateDir string, publicKeyPath string) (Daemon, error) {
	thresholdScheme := crypto.NewBLSSuite()
	dkgCoordinator := dkg.NewDKGCoordinator(publicURL, thresholdScheme)
	return NewDaemonWithDKG(port, publicURL, stateDir, dkgCoordinator, publicKeyPath)
}

func NewDaemonWithDKG(port uint, publicURL string, stateDir string, coordinator DKGProtocol, publicKeyPath string) (Daemon, error) {
	if port == 0 {
		return Daemon{}, errors.New("you must provide a port")
	}

	if stateDir == "" {
		return Daemon{}, errors.New("you must pass a valid path to a keypair")
	}

	if publicKeyPath == "" {
		return Daemon{}, errors.New("you must pass the path to your SSV node's public key")
	}

	if publicURL == "" {
		return Daemon{}, errors.New("you must pass a public URL flag")
	}
	if _, err := url.Parse(publicURL); err != nil {
		return Daemon{}, errors.New("you must pass a public URL flag")
	}

	keypair, err := util.LoadKeypair(stateDir)
	if err != nil {
		return Daemon{}, fmt.Errorf("error loading keypair: %w", err)
	}

	ssvKey, err := util.LoadSsvPublicKey(publicKeyPath)
	if err != nil {
		return Daemon{}, fmt.Errorf("error loading ssv key: %w", err)
	}

	slog.Info(fmt.Sprintf("Keypair loaded from %s", stateDir))

	thresholdScheme := crypto.NewBLSSuite()
	daemon := Daemon{
		port:             port,
		key:              keypair,
		publicURL:        publicURL,
		ssvKey:           ssvKey,
		stateDir:         stateDir,
		dkg:              coordinator,
		db:               dkg.NewFileStore(stateDir),
		thresholdScheme:  thresholdScheme,
		encryptionScheme: crypto.NewRSASuite(),
	}
	router := createAPI(daemon)
	daemon.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: router,
	}

	return daemon, nil
}

func (d Daemon) Start() chan error {
	errs := make(chan error, 1)

	go func() {
		err := d.server.ListenAndServe()
		errs <- err
	}()

	return errs
}

func (d Daemon) Stop() {
	err := d.server.Shutdown(context.Background())
	if err != nil {
		slog.Error("error shutting down server", err)
		os.Exit(1)
	}
}
