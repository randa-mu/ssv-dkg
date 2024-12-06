package dkg

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"reflect"
	"sync"

	"golang.org/x/exp/slices"

	"github.com/drand/kyber"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"

	"github.com/randa-mu/ssv-dkg/shared/crypto"
)

type GroupFile struct {
	SessionID                   string            `json:"session_id"`
	Nodes                       []crypto.Identity `json:"nodes"`
	PublicPolynomialCommitments []byte            `json:"public_polynomial_commitments"`
	KeyShare                    []byte            `json:"key_share"`
	EncryptedKeyShareHash       []byte            `json:"encrypted_key_share_hash"`
}

type DistPublic struct {
	Coefficients []kyber.Point
}

type FileStore struct {
	lock sync.Mutex
	path string
}

type GroupFiles struct {
	SessionID  string      `json:"session_id"`
	GroupFiles []GroupFile `json:"group_files"`
}

func NewFileStore(path string) *FileStore {
	return &FileStore{
		lock: sync.Mutex{},
		path: path,
	}
}

// Save checks for any state for a given sessionID, and stores the new group file as part of it
func (f *FileStore) Save(group GroupFile) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	sessionID := group.SessionID

	g, err := f.Load(sessionID)
	if err != nil {
		return err
	}

	var groupFiles GroupFiles
	if reflect.DeepEqual(g, GroupFiles{}) {
		groupFiles = GroupFiles{
			SessionID:  sessionID,
			GroupFiles: []GroupFile{group},
		}
	} else {
		groupFiles = GroupFiles{
			SessionID:  sessionID,
			GroupFiles: append(g.GroupFiles, group),
		}
	}

	p := path.Join(f.path, fmt.Sprintf("%s.json", sessionID))
	b, err := json.Marshal(groupFiles)
	if err != nil {
		return err
	}

	return os.WriteFile(p, b, 0o644)
}

// Load loads a set of group files associated with a given sessionID
// if none exist, it returns an empty `GroupFiles` object
func (f *FileStore) Load(sessionID string) (GroupFiles, error) {
	p := path.Join(f.path, fmt.Sprintf("%s.json", sessionID))

	b, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return GroupFiles{}, nil
		}
		return GroupFiles{}, err
	}
	var output GroupFiles
	err = json.Unmarshal(b, &output)
	if err != nil {
		return GroupFiles{}, err
	}
	return output, nil
}

// LoadSingle loads a group file given an encryptedShareHash
// in some scenarios, we can complete a reshare and store a share, though someone in the wider
// group had errors; in this case, the caller will re-run the reshare, and tell use which share to use
// by passing the hash of the encrypted share
func (f *FileStore) LoadSingle(sessionID string, encryptedShareHash []byte) (GroupFile, error) {
	// if the caller didn't give us an encrypted share hash, we can assume we weren't in the last group
	if encryptedShareHash == nil {
		return GroupFile{}, nil
	}

	// in principle, if we receive an `encryptedShareHash`, we should _really_ have state
	groupFiles, err := f.Load(sessionID)
	if err != nil {
		return GroupFile{}, err
	}
	if reflect.DeepEqual(GroupFiles{}, groupFiles) {
		return GroupFile{}, errors.New("could not find state for the encrypted share")
	}

	for _, g := range groupFiles.GroupFiles {
		if bytes.Equal(g.EncryptedKeyShareHash, encryptedShareHash) {
			return g, nil
		}
	}

	return GroupFile{}, nil
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

func NewGroupFile(sessionID string, pubPoly []byte, nodes []crypto.Identity, share, encryptedShare []byte) (GroupFile, error) {
	slices.SortFunc(nodes, func(a, b crypto.Identity) int {
		return bytes.Compare(a.Public, b.Public)
	})

	s := sha256.New()
	_, err := s.Write(encryptedShare)
	if err != nil {
		return GroupFile{}, err
	}
	encryptedShareHash := s.Sum(nil)

	return GroupFile{
		SessionID:                   sessionID,
		Nodes:                       nodes,
		PublicPolynomialCommitments: pubPoly,
		KeyShare:                    share,
		EncryptedKeyShareHash:       encryptedShareHash,
	}, nil
}
