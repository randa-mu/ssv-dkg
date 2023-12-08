package dkg

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/sign/schnorr"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"golang.org/x/exp/slog"
	"sort"
	"time"
)

type DKGCoordinator struct {
	publicURL string
	board     *DKGBoard
	scheme    crypto.ThresholdScheme
}

func NewDKGCoordinator(publicURL string, scheme crypto.ThresholdScheme) DKGCoordinator {
	return DKGCoordinator{
		publicURL: publicURL,
		scheme:    scheme,
		board:     nil,
	}
}

func (d *DKGCoordinator) RunDKG(identities []crypto.Identity, sessionID []byte, keypair crypto.Keypair) (*dkg.Result, error) {
	numberOfNodes := len(identities)
	threshold := dkg.MinimumT(numberOfNodes)
	keyGroup := d.scheme.KeyGroup()

	secretKey := keyGroup.Scalar()
	err := secretKey.UnmarshalBinary(keypair.Private)
	if err != nil {
		return nil, err
	}

	// we sort the identities by their public key, so that everyone has the same view
	sort.SliceStable(identities, func(i, j int) bool {
		return bytes.Compare(identities[i].Public, identities[j].Public) > 0
	})

	// we map the identities into the DKG node format and extract the addresses we want to gossip to (not ourselves)
	nodes := make([]dkg.Node, numberOfNodes)
	var addresses []string
	for i, identity := range identities {
		// turn the public key into a kyber point
		pk := keyGroup.Point()
		err = pk.UnmarshalBinary(identity.Public)
		if err != nil {
			return nil, err
		}

		// map it into the DKG struct
		nodes[i] = dkg.Node{
			Index:  uint32(i),
			Public: pk,
		}
		// if it's not our node, we'd like to gossip packets to it
		if identity.Address != d.publicURL {
			addresses = append(addresses, identity.Address)
		}
	}

	config := dkg.Config{
		Suite:          keyGroup.(dkg.Suite),
		Longterm:       secretKey,
		OldNodes:       nil,
		PublicCoeffs:   nil,
		NewNodes:       nodes,
		Share:          nil,
		Threshold:      threshold,
		OldThreshold:   0,
		Reader:         rand.Reader,
		UserReaderOnly: false,
		FastSync:       false,
		Nonce:          sessionID,
		Auth:           schnorr.NewScheme(&crypto.SchnorrSuite{Group: keyGroup}),
		Log:            dkgLogger{},
	}

	d.board = NewDKGBoard(addresses)
	p := dkg.NewTimePhaser(5 * time.Second)
	protocol, err := dkg.NewProtocol(&config, d.board, p, true)
	if err != nil {
		return nil, err
	}

	go p.Start()
	select {
	case result := <-protocol.WaitEnd():
		return result.Result, result.Error
	case <-time.After(1 * time.Minute):
		return nil, fmt.Errorf("DKG with sessionID %s timed out", hex.EncodeToString(sessionID))
	}
}

func (d *DKGCoordinator) ProcessPacket(packet api.SidecarDKGPacket) error {
	if packet.Deal != nil {
		slog.Debug(fmt.Sprintf("received deal from %d", packet.Deal.DealerIndex))
		bundle, err := packet.Deal.ToDomain(d.scheme)
		if err != nil {
			return err
		}

		d.board.PushDeals(&bundle)

	} else if packet.Response != nil {
		slog.Debug(fmt.Sprintf("received response from %d", packet.Response.ShareIndex))
		d.board.PushResponses(&packet.Response.ResponseBundle)

	} else if packet.Justification != nil {
		slog.Debug(fmt.Sprintf("received justification from %d", packet.Justification.DealerIndex))
		bundle, err := packet.Justification.ToDomain(d.scheme)
		if err != nil {
			return err
		}
		d.board.PushJustifications(&bundle)

	} else {
		slog.Error("received a DKG packet with nothing in it")
		return errors.New("DKG packet was empty")
	}
	return nil
}

type dkgLogger struct {
}

func (d dkgLogger) Info(keyvals ...interface{}) {
	slog.Info("", keyvals)
}

func (d dkgLogger) Error(keyvals ...interface{}) {
	slog.Error("", keyvals)
}
