package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"github.com/drand/kyber"
	"github.com/randa-mu/ssv-dkg/shared/encoding"
)

// SigningScheme represents a cryptographic scheme used for signing and verification operations
type SigningScheme interface {
	CreateKeypair() (Keypair, error)
	Sign(keypair Keypair, message []byte) ([]byte, error)
	Verify(message []byte, publicKey []byte, signature []byte) error
}

type ThresholdScheme interface {
	SigningScheme
	KeyGroup() kyber.Group
	SignWithPartial(private []byte, msg []byte) ([]byte, error)
	VerifyPartial(publicPolynomial []byte, msg, sig []byte) error
	AggregateSignatures(sigs ...[]byte) ([]byte, error)
	AggregatePublicKeys(publicKeys ...[]byte) ([]byte, error)
	RecoverSignature(message []byte, pubPoly []byte, sigs [][]byte, nodeCount int) ([]byte, error)
	VerifyRecovered(message []byte, publicKey []byte, signature []byte) error
}

type EncryptionScheme interface {
	Encrypt(publicKey []byte, plaintext []byte) ([]byte, error)
	Decrypt(privateKey []byte, ciphertext []byte) ([]byte, error)
}

type Keypair struct {
	Private []byte `json:"private"`
	Public  []byte `json:"public"`
}

// SelfSign signs an address to attribute it to a given public key and returns an Identity
func (k Keypair) SelfSign(suite SigningScheme, address string, operatorID uint32) (Identity, error) {
	message, err := digestFor(k.Public, address, operatorID)
	if err != nil {
		return Identity{}, err
	}

	signature, err := suite.Sign(k, message)
	if err != nil {
		return Identity{}, err
	}

	return Identity{
		OperatorID: operatorID,
		Address:    address,
		Public:     k.Public,
		Signature:  signature,
	}, nil
}

type Identity struct {
	OperatorID uint32                 `json:"operator_id"`
	Address    string                 `json:"address"`
	Public     encoding.UnpaddedBytes `json:"public"`
	Signature  encoding.UnpaddedBytes `json:"signature"`
}

// Verify checks the signature for a given identity is valid, if e.g. pulled from a remote file
func (i Identity) Verify(suite SigningScheme) error {
	m, err := digestFor(i.Public, i.Address, i.OperatorID)
	if err != nil {
		return err
	}
	return suite.Verify(m, i.Public, i.Signature)
}

func digestFor(publicKey []byte, address string, operatorID uint32) ([]byte, error) {
	buf := new(bytes.Buffer)

	dst := []byte("ssv:randamu:sha256")
	if err := binary.Write(buf, binary.BigEndian, dst); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, publicKey); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, []byte(address)); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, operatorID); err != nil {
		return nil, err
	}

	out := sha256.New()
	if _, err := out.Write(buf.Bytes()); err != nil {
		return nil, err
	}
	return out.Sum(nil), nil
}
