package stub

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
)

func StartStub(port uint) func() {
	suite := crypto.NewRSASuite()
	kp, err := suite.CreateKeypair()
	if err != nil {
		shared.Exit(fmt.Sprintf("failed to generate RSA keypair: %v", err))
	}

	router := chi.NewMux()

	stop := make(chan bool, 1)
	s := stub{
		keypair: kp,
		port:    port,
		router:  router,
		stop:    stop,
	}

	api.BindSSVApi(router, s)

	go func() {
		s.Start()
	}()

	return func() {
		close(stop)
	}
}

type stub struct {
	keypair crypto.Keypair
	port    uint
	router  *chi.Mux
	stop    chan bool
}

func (s stub) Start() {
	server := http.Server{
		Addr:    fmt.Sprintf(":%d", s.port),
		Handler: s.router,
	}

	go func() {
		fmt.Printf("starting stub on port %d\n", s.port)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			shared.Exit(fmt.Sprintf("error starting SSV stub: %v", err))
		}
	}()

	<-s.stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		shared.Exit("error shutting down SSV stub server")
	}
	fmt.Println("stub server stopped")
}

func (s stub) Health() error {
	return nil
}

func (s stub) Identity() (api.SsvIdentityResponse, error) {
	return api.SsvIdentityResponse{
		PublicKey: s.keypair.Public,
	}, nil
}
