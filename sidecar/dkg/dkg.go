package dkg

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/exp/slices"
	"golang.org/x/exp/slog"

	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/sign/schnorr"

	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
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

	// we map the identities into the DKG node format and extract the addresses we want to gossip to (not ourselves)
	nodes, err := prepareIdentities(d.scheme, identities)
	if err != nil {
		return nil, err
	}

	var addresses []string
	for _, identity := range identities {
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
		Log:            dkgLogger{address: d.publicURL},
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
		output, err := AsResult(d.scheme, numberOfNodes, result.Result)
		if err != nil {
			return nil, err
		}
		return &output, result.Error

	case <-time.After(d.timeout):
		return nil, fmt.Errorf("DKG with sessionID %s timed out", hex.EncodeToString(sessionID))
	}
}

func (d *Coordinator) RunReshare(identities []crypto.Identity, sessionID []byte, keypair crypto.Keypair, state GroupFile) (*Output, error) {
	numberOfNodes := len(identities)
	threshold := dkg.MinimumT(numberOfNodes)
	oldThreshold := dkg.MinimumT(len(state.Nodes))
	keyGroup := d.scheme.KeyGroup()

	secretKey := keyGroup.Scalar()
	err := secretKey.UnmarshalBinary(keypair.Private)
	if err != nil {
		return nil, err
	}

	pubPoly, err := crypto.UnmarshalPubPoly(d.scheme, state.PublicPolynomialCommitments)
	if err != nil {
		return nil, err
	}
	_, polynomialCommitments := pubPoly.Info()

	oldNodes, err := prepareIdentities(d.scheme, state.Nodes)
	if err != nil {
		return nil, err
	}

	newNodes, err := prepareIdentities(d.scheme, identities)
	if err != nil {
		return nil, err
	}

	var addresses []string
	for _, identity := range identities {
		// if it's not our node, we'd like to gossip packets to it
		if identity.Address != d.publicURL {
			addresses = append(addresses, identity.Address)
		}
	}

	// new nodes won't have a key share, so they just pass `nil` to the DKG config
	var distKey *dkg.DistKeyShare
	if state.KeyShare != nil {
		s, err := crypto.UnmarshalDistKey(d.scheme, state.KeyShare)
		if err != nil {
			return nil, err
		}
		distKey = &dkg.DistKeyShare{
			Commits: polynomialCommitments,
			Share:   &s,
		}
	} else {
		slog.Debug("no existing share for resharing")
	}

	config := dkg.Config{
		Suite:          keyGroup.(dkg.Suite),
		Longterm:       secretKey,
		PublicCoeffs:   polynomialCommitments,
		OldNodes:       oldNodes,
		NewNodes:       newNodes,
		Share:          distKey,
		Threshold:      threshold,
		OldThreshold:   oldThreshold,
		UserReaderOnly: false,
		FastSync:       false,
		Nonce:          sessionID,
		Auth:           schnorr.NewScheme(&crypto.SchnorrSuite{Group: keyGroup}),
		Log:            dkgLogger{address: d.publicURL},
	}

	d.board = NewDKGBoard(addresses)
	phaser := dkg.NewTimePhaser(5 * time.Second)
	protocol, err := dkg.NewProtocol(&config, d.board, phaser, false)
	if err != nil {
		return nil, err
	}

	go phaser.Start()
	select {
	case result := <-protocol.WaitEnd():
		if result.Error != nil {
			return nil, result.Error
		}
		output, err := AsResult(d.scheme, numberOfNodes, result.Result)
		return &output, err
	case <-time.After(d.timeout):
		return nil, fmt.Errorf("reshare with sessionID %s timed out", hex.EncodeToString(sessionID))
	}
}

func prepareIdentities(scheme crypto.ThresholdScheme, identities []crypto.Identity) ([]dkg.Node, error) {
	// sortby operatorID so everyone has a consistent view of the world
	slices.SortStableFunc(identities, func(i, j crypto.Identity) int {
		return int(i.OperatorID) - int(j.OperatorID)
	})

	// then map them into magical DKG structs
	nodes := make([]dkg.Node, len(identities))
	for i, identity := range identities {
		ident := identity
		p := scheme.KeyGroup().Point().Clone()
		err := p.UnmarshalBinary(ident.Public)
		if err != nil {
			return nil, err
		}
		nodes[i] = dkg.Node{
			Index:  uint32(i + 1),
			Public: p,
		}
	}

	return nodes, nil
}

func (d *Coordinator) ProcessPacket(packet api.SidecarDKGPacket) error {
	// maybe this should repeat? if a node responds error to the client, then subsequent attempts to do a DKG will fail
	if d.board == nil {
		return errors.New("DKG not started yet")
	}
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
	address string
}

func (d dkgLogger) Info(keyvals ...interface{}) {
	slog.Info("dkg", "message", fmt.Sprintf("%s", keyvals), "address", d.address)
}

func (d dkgLogger) Error(keyvals ...interface{}) {
	slog.Error("dkg", "error", fmt.Sprintf("%s", keyvals), "address", d.address)
}

func AsResult(scheme crypto.ThresholdScheme, countOfNodes int, result *dkg.Result) (Output, error) {
	if result == nil || result.Key == nil {
		return Output{}, errors.New("DKG result was nil")
	}

	if countOfNodes != len(result.QUAL) {
		return Output{}, fmt.Errorf("expected %d nodes to complete the DKG, but only %d completed it", countOfNodes, len(result.QUAL))
	}

	distKey, err := crypto.MarshalDistKey(result.Key.Share)
	if err != nil {
		return Output{}, err
	}

	pubPoly, err := crypto.MarshalPubPoly(share.NewPubPoly(scheme.KeyGroup(), scheme.KeyGroup().Point().Base().Clone(), result.Key.Commits))
	if err != nil {
		return Output{}, err
	}

	pubKey, err := result.Key.Public().MarshalBinary()
	if err != nil {
		return Output{}, err
	}

	// we fail the DKG if any node doesn't make it, so we can safely assume there will be a node at each index
	slices.SortStableFunc(result.QUAL, func(a, b dkg.Node) int {
		return int(a.Index - b.Index)
	})
	pubKeys := make([][]byte, len(result.QUAL))
	for i, node := range result.QUAL {
		n := node
		pk, err := n.Public.MarshalBinary()
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
