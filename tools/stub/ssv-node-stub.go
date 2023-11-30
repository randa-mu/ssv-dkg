package stub

import (
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"net/http"
)

func StartStub(port uint) {
	suite := crypto.NewRSASuite()
	kp, err := suite.CreateKeypair()
	if err != nil {
		shared.Exit(fmt.Sprintf("failed to generate RSA keypair: %v", err))
	}

	router := chi.NewMux()

	s := stub{
		keypair: kp,
		port:    port,
		router:  router,
	}

	api.BindSSVApi(router, s)

	s.Start()
}

type stub struct {
	keypair crypto.Keypair
	port    uint
	router  *chi.Mux
}

func (s stub) Start() {
	fmt.Printf("starting stub on port %d\n", s.port)
	err := http.ListenAndServe(fmt.Sprintf(":%d", s.port), s.router)
	if err != nil {
		shared.Exit(fmt.Sprintf("error starting SSV stub: %v", err))
	}
}

func (s stub) Health() error {
	return nil
}

func (s stub) Identity() (api.SsvIdentityResponse, error) {
	return api.SsvIdentityResponse{
		PublicKey: s.keypair.Public,
		Nonce:     1,
	}, nil
}
