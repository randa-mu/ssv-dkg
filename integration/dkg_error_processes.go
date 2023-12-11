package integration

import (
	"errors"
	"github.com/drand/kyber/share/dkg"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	dkg2 "github.com/randa-mu/ssv-dkg/sidecar/dkg"
)

type ErrorStartingDKG struct {
}

func (e ErrorStartingDKG) RunDKG(identities []crypto.Identity, sessionID []byte, keypair crypto.Keypair) (*dkg.Result, error) {
	return nil, errors.New("simulated error starting DKG")
}

func (e ErrorStartingDKG) ProcessPacket(packet api.SidecarDKGPacket) error {
	panic("implement me")
}

type ErrorDuringDKG struct {
	url    string
	scheme crypto.ThresholdScheme
}

func (e ErrorDuringDKG) RunDKG(identities []crypto.Identity, sessionID []byte, keypair crypto.Keypair) (*dkg.Result, error) {
	d := dkg2.NewDKGCoordinator(e.url, e.scheme)
	return d.RunDKG(identities, sessionID, keypair)
}

func (e ErrorDuringDKG) ProcessPacket(packet api.SidecarDKGPacket) error {
	return errors.New("simulated error reading packet")
}
