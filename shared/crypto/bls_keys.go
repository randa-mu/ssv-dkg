package crypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/sign"
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
	suite := bls.NewBLS12381Suite()
	scheme := signing.NewSchemeOnG1(suite)
	return blsSuite{scheme: scheme, suite: suite, thresholdScheme: tbls.NewThresholdSchemeOnG1(suite)}
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

func (b blsSuite) Sign(keypair Keypair, message []byte) ([]byte, error) {
	sk := b.KeyGroup().Scalar()
	err := sk.UnmarshalBinary(keypair.Private)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
	}

	return b.scheme.Sign(sk, message)
}

func (b blsSuite) Verify(message []byte, publicKey []byte, signature []byte) error {
	pk := b.KeyGroup().Point()
	err := pk.UnmarshalBinary(publicKey)
	if err != nil {
		return fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	return b.scheme.Verify(pk, message, signature)
}

func (b blsSuite) KeyGroup() kyber.Group {
	return b.KeyGroup()
}

func (b blsSuite) SignWithPartial(private []byte, message []byte) ([]byte, error) {
	distKey, err := UnmarshalDistKey(b, private)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, uint16(distKey.I)); err != nil {
		return nil, err
	}
	m := b.Digest(message)
	sig, err := b.scheme.Sign(distKey.V, m)
	if err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, sig); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (b blsSuite) VerifyPartial(public []byte, msg, sig []byte) error {
	pubPoly, err := UnmarshalPubPoly(b, public)
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
	m := b.Digest(msg)
	return b.Verify(m, V, sh.Value())
}

func (b blsSuite) RecoverSignature(message []byte, pubPoly []byte, sigs [][]byte, nodeCount int) ([]byte, error) {
	threshold := dkg.MinimumT(nodeCount)
	p, err := UnmarshalPubPoly(b, pubPoly)
	if err != nil {
		return nil, err
	}
	m := b.Digest(message)
	return b.thresholdScheme.Recover(&p, m, sigs, threshold, nodeCount)
}

func (b blsSuite) VerifyRecovered(message []byte, publicKey []byte, signature []byte) error {
	p, err := UnmarshalPubPoly(b, publicKey)
	if err != nil {
		return err
	}
	m := b.Digest(message)
	return b.thresholdScheme.VerifyRecovered(p.Commit(), m, signature)
}

func (b blsSuite) Digest(msg []byte) []byte {
	h := sha256.New()
	h.Write(msg)
	return h.Sum(nil)
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

func (s *SigShare) Value() []byte {
	return []byte(*s)[2:]
}

type SchnorrSuite struct {
	kyber.Group
}

func (s *SchnorrSuite) RandomStream() cipher.Stream {
	return random.New()
}
