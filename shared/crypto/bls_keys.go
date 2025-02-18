package crypto

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/sign"
	"github.com/ethereum/go-ethereum/crypto"

	//nolint:staticcheck //only a rogue key attack if used wrong
	signing "github.com/drand/kyber/sign/bls"
	"github.com/drand/kyber/sign/tbls"
	"github.com/drand/kyber/util/random"
)

type blsSuite struct {
	suite           pairing.Suite
	scheme          sign.AggregatableScheme
	thresholdScheme sign.ThresholdScheme
}

func NewBLSSuite() blsSuite {
	suite := bls.NewBLS12381SuiteWithDST([]byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"), []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"))
	scheme := signing.NewSchemeOnG2(suite)
	return blsSuite{scheme: scheme, suite: suite, thresholdScheme: tbls.NewThresholdSchemeOnG2(suite)}
}

func (b blsSuite) CreateKeypair() (Keypair, error) {
	privateKey, publicKey := b.scheme.NewKeyPair(random.New())

	skBytes, err := privateKey.MarshalBinary()
	if err != nil {
		return Keypair{}, err
	}

	pkBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return Keypair{}, err
	}

	return Keypair{
		Public:  pkBytes,
		Private: skBytes,
	}, nil
}

// Sign works with the raw message, make sure to use Digest first if you need it
func (b blsSuite) Sign(keypair Keypair, messageRaw []byte) ([]byte, error) {
	sk := b.KeyGroup().Scalar()
	err := sk.UnmarshalBinary(keypair.Private)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
	}

	return b.scheme.Sign(sk, messageRaw)
}

// Verify works with the raw message, make sure to use Digest first if you need it
func (b blsSuite) Verify(messageRaw []byte, publicKey []byte, signature []byte) error {
	pk := b.KeyGroup().Point().Base().Clone()
	err := pk.UnmarshalBinary(publicKey)
	if err != nil {
		return fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	return b.scheme.Verify(pk, messageRaw, signature)
}

func (b blsSuite) KeyGroup() kyber.Group {
	return b.suite.G1()
}

func (b blsSuite) SignWithPartial(private []byte, messageRaw []byte) ([]byte, error) {
	distKey, err := UnmarshalDistKey(b, private)
	if err != nil {
		return nil, err
	}
	return b.thresholdScheme.Sign(&distKey, messageRaw)
}

func (b blsSuite) VerifyPartial(publicCoefficients []byte, msg, sig []byte) error {
	pubPoly, err := UnmarshalPubPoly(b, publicCoefficients)
	if err != nil {
		return err
	}
	sh := SigShare(sig)
	i, err := sh.Index()
	if err != nil {
		return err
	}
	V, err := pubPoly.Eval(i).V.MarshalBinary()
	if err != nil {
		return err
	}

	return b.Verify(msg, V, sh.Value())
}

func (b blsSuite) RecoverSignature(message []byte, pubPoly []byte, sigs [][]byte, nodeCount int) ([]byte, error) {
	threshold := dkg.MinimumT(nodeCount)
	p, err := UnmarshalPubPoly(b, pubPoly)
	if err != nil {
		return nil, err
	}

	return b.thresholdScheme.Recover(&p, message, sigs, threshold, nodeCount)
}

func (b blsSuite) VerifyRecovered(message []byte, publicCoefficients []byte, signature []byte) error {
	p, err := UnmarshalPubPoly(b, publicCoefficients)
	if err != nil {
		return err
	}

	return b.thresholdScheme.VerifyRecovered(p.Commit(), message, signature)
}

func (b blsSuite) Digest(msg []byte) []byte {
	return crypto.Keccak256(msg)
}

func (b blsSuite) AggregateSignatures(sigs ...[]byte) ([]byte, error) {
	return b.scheme.AggregateSignatures(sigs...)
}

func (b blsSuite) AggregatePublicKeys(publicKeys ...[]byte) ([]byte, error) {
	points := make([]kyber.Point, len(publicKeys))
	for i, key := range publicKeys {
		p := b.KeyGroup().Point()
		err := p.UnmarshalBinary(key)
		if err != nil {
			return nil, err
		}
		points[i] = p
	}

	aggregatedPublicKey := b.scheme.AggregatePublicKeys(points...)
	return aggregatedPublicKey.MarshalBinary()
}

type SigShare []byte

func (s SigShare) Index() (int, error) {
	var index uint16
	buf := bytes.NewReader(s)
	err := binary.Read(buf, binary.BigEndian, &index)
	if err != nil {
		return -1, err
	}
	return int(index), nil
}

// Value trims the first two bytes because they encode the DKG index
func (s *SigShare) Value() []byte {
	return []byte(*s)[2:]
}

type SchnorrSuite struct {
	kyber.Group
}

func (s *SchnorrSuite) RandomStream() cipher.Stream {
	return random.New()
}
