package crypto

import (
	"fmt"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/pairing"

	"github.com/drand/kyber/sign"
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
	sk := b.suite.G1().Scalar()
	err := sk.UnmarshalBinary(keypair.Private)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %v", err)
	}

	return b.scheme.Sign(sk, message)
}

func (b blsSuite) Verify(message []byte, publicKey []byte, signature []byte) error {
	pk := b.suite.G1().Point()
	err := pk.UnmarshalBinary(publicKey)
	if err != nil {
		return fmt.Errorf("failed to unmarshal public key: %v", err)
	}

	return b.scheme.Verify(pk, message, signature)
}
