package dkg

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/sign/schnorr"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"golang.org/x/exp/slog"
)

type Coordinator struct {
	publicURL string
	board     *DKGBoard
	scheme    crypto.ThresholdScheme
	timeout   time.Duration
}

type Output struct {
	PublicKeyShare  []byte
	GroupPublicPoly []byte
	KeyShare        []byte
	NodePublicKeys  [][]byte
}

func NewDKGCoordinator(publicURL string, scheme crypto.ThresholdScheme) *Coordinator {
	return &Coordinator{
		publicURL: publicURL,
		scheme:    scheme,
		board:     nil,
		timeout:   1 * time.Minute,
	}
}

func (d *Coordinator) RunDKG(identities []crypto.Identity, sessionID []byte, keypair crypto.Keypair) (*Output, error) {
	numberOfNodes := len(identities)
	threshold := dkg.MinimumT(numberOfNodes)
	keyGroup := d.scheme.KeyGroup()

	secretKey := keyGroup.Scalar()
	err := secretKey.UnmarshalBinary(keypair.Private)
	if err != nil {
		return nil, err
	}

	// we sort the identities by their public key, so that everyone has the same order
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
	protocol, err := dkg.NewProtocol(&config, d.board, p, false)
	if err != nil {
		return nil, err
	}

	go p.Start()
	select {
	case result := <-protocol.WaitEnd():
		output, err := AsResult(d.scheme, result.Result)
		if err != nil {
			return nil, err
		}
		return &output, result.Error
	case <-time.After(d.timeout):
		return nil, fmt.Errorf("DKG with sessionID %s timed out", hex.EncodeToString(sessionID))
	}
}

func (d *Coordinator) ProcessPacket(packet api.SidecarDKGPacket) error {
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
	slog.Info("dkg", "message", fmt.Sprintf("%s", keyvals))
}

func (d dkgLogger) Error(keyvals ...interface{}) {
	slog.Error("dkg", "error", fmt.Sprintf("%s", keyvals))
}

func AsResult(scheme crypto.ThresholdScheme, result *dkg.Result) (Output, error) {
	distKey, err := crypto.MarshalDistKey(result.Key.Share)
	if err != nil {
		return Output{}, err
	}

	pubPoly, err := crypto.MarshalPubPoly(share.NewPubPoly(scheme.KeyGroup(), result.Key.Public(), result.Key.Commits))
	if err != nil {
		return Output{}, err
	}

	pubKey, err := result.Key.Public().MarshalBinary()
	if err != nil {
		return Output{}, err
	}

	// we fail the DKG if any node doesn't make it, so we can safely assume there will be a node at each index
	sort.Slice(result.QUAL, func(i, j int) bool {
		return result.QUAL[i].Index < result.QUAL[j].Index
	})
	pubKeys := make([][]byte, len(result.QUAL))
	for i, node := range result.QUAL {
		pk, err := node.Public.MarshalBinary()
		if err != nil {
			return Output{}, err
		}
		pubKeys[i] = pk
	}

	return Output{
		KeyShare:        distKey,
		PublicKeyShare:  pubKey,
		GroupPublicPoly: pubPoly,
		NodePublicKeys:  pubKeys,
	}, nil
}
