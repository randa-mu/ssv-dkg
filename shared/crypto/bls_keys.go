package crypto

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/share"

	"github.com/drand/kyber/sign"
	//nolint:staticcheck //only a rogue key attack if used wrong
	signing "github.com/drand/kyber/sign/bls"
	"github.com/drand/kyber/util/random"
)

type blsSuite struct {
	suite  pairing.Suite
	scheme sign.AggregatableScheme
}

func NewBLSSuite() blsSuite {
	suite := bls.NewBLS12381Suite()
	scheme := signing.NewSchemeOnG2(suite)
	return blsSuite{scheme: scheme, suite: suite}
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
		return nil, fmt.Errorf("failed to unmarshal private key: %v", err)
	}

	return b.scheme.Sign(sk, message)
}

func (b blsSuite) Verify(message []byte, publicKey []byte, signature []byte) error {
	pk := b.KeyGroup().Point()
	err := pk.UnmarshalBinary(publicKey)
	if err != nil {
		return fmt.Errorf("failed to unmarshal public key: %v", err)
	}

	return b.scheme.Verify(pk, message, signature)
}

func (b blsSuite) KeyGroup() kyber.Group {
	return b.suite.G1()
}

func (b blsSuite) SignWithPartial(private *share.PriShare, message []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, uint16(private.I)); err != nil {
		return nil, err
	}
	sig, err := b.scheme.Sign(private.V, message)
	if err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, sig); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (b blsSuite) VerifyPartial(public *share.PubPoly, msg, sig []byte) error {
	sh := SigShare(sig)
	i, err := sh.Index()
	if err != nil {
		return err
	}
	V, err := public.Eval(i).V.MarshalBinary()
	if err != nil {
		return err
	}
	return b.Verify(msg, V, sh.Value())
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
