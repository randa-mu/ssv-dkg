package dkg

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/drand/kyber"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"golang.org/x/exp/slices"
)

type GroupFile struct {
	SessionID                   string            `json:"session_id"`
	Threshold                   uint32            `json:"threshold"`
	Nodes                       []crypto.Identity `json:"nodes"`
	PublicPolynomialCommitments []byte            `json:"public_polynomial_commitments"`
	KeyShare                    []byte            `json:"key_share"`
}
type DistPublic struct {
	Coefficients []kyber.Point
}

// Share represents the private information that a node holds after a successful
// DKG. This information MUST stay private !
type Share struct {
	dkg.DistKeyShare
	Scheme crypto.ThresholdScheme
}

// PubPoly returns the public polynomial that can be used to verify any
// individual partial signature
func (s *Share) PubPoly() *share.PubPoly {
	return share.NewPubPoly(s.Scheme.KeyGroup(), s.Scheme.KeyGroup().Point().Base(), s.Commits)
}

// PrivateShare returns the private share used to produce a partial signature
func (s *Share) PrivateShare() *share.PriShare {
	return s.Share
}

// Public returns the distributed public key associated with the distributed key
// share
func (s *Share) Public() DistPublic {
	return DistPublic{s.Commits}
}

func NewGroupFile(sessionID string, threshold uint32, pubPoly []byte, nodes []crypto.Identity, share []byte) GroupFile {
	slices.SortFunc(nodes, func(a, b crypto.Identity) int {
		return bytes.Compare(a.Public, b.Public)
	})
	group := GroupFile{
		SessionID:                   sessionID,
		Threshold:                   threshold,
		Nodes:                       nodes,
		PublicPolynomialCommitments: pubPoly,
		KeyShare:                    share,
	}

	return group
}

func StoreDKG(stateDir, sessionID string, response *Output, identities []crypto.Identity) error {
	threshold := dkg.MinimumT(len(response.NodePublicKeys))
	p := path.Join(stateDir, fmt.Sprintf("%s.json", sessionID))
	groupFile := NewGroupFile(sessionID, uint32(threshold), response.GroupPublicPoly, identities, response.KeyShare)
	b, err := json.Marshal(groupFile)
	if err != nil {
		return err
	}

	return os.WriteFile(p, b, 0644)
}

func LoadDKG(stateDir, sessionID string) (GroupFile, error) {
	p := path.Join(stateDir, fmt.Sprintf("%s.json", sessionID))

	b, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return GroupFile{}, nil
		}
		return GroupFile{}, err
	}
	var output GroupFile
	err = json.Unmarshal(b, &output)
	if err != nil {
		return GroupFile{}, err
	}
	return output, nil
}
