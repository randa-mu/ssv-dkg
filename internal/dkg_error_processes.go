package internal

import (
	"errors"

	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"github.com/randa-mu/ssv-dkg/sidecar/dkg"
)

type ErrorStartingDKG struct{}

func (e ErrorStartingDKG) RunDKG(identities []crypto.Identity, sessionID []byte, keypair crypto.Keypair) (*dkg.Output, error) {
	return nil, errors.New("simulated error starting DKG")
}

func (e ErrorStartingDKG) RunReshare(identities []crypto.Identity, sessionID []byte, keypair crypto.Keypair, state dkg.GroupFile) (*dkg.Output, error) {
	return nil, errors.New("simulated error running reshare")
}

func (e ErrorStartingDKG) ProcessPacket(packet api.SidecarDKGPacket) error {
	return errors.New("processing packet is undefined for the error DKG")
}

type ErrorDuringDKG struct {
	url    string
	scheme crypto.ThresholdScheme
}

func (e ErrorDuringDKG) RunDKG(identities []crypto.Identity, sessionID []byte, keypair crypto.Keypair) (*dkg.Output, error) {
	d := dkg.NewDKGCoordinator(e.url, e.scheme)
	return d.RunDKG(identities, sessionID, keypair)
}

func (e ErrorDuringDKG) RunReshare(identities []crypto.Identity, sessionID []byte, keypair crypto.Keypair, state dkg.GroupFile) (*dkg.Output, error) {
	return nil, errors.New("simulated error running reshare")
}

func (e ErrorDuringDKG) ProcessPacket(packet api.SidecarDKGPacket) error {
	return errors.New("simulated error reading packet")
}
