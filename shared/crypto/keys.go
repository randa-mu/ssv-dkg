package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"github.com/drand/kyber"
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
	VerifyPartial(public []byte, msg, sig []byte) error
	AggregateSignatures(sigs ...[]byte) ([]byte, error)
	AggregatePublicKeys(publicKeys ...[]byte) ([]byte, error)
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
func (k Keypair) SelfSign(suite SigningScheme, address string, nonce uint32) (Identity, error) {
	message, err := digestFor(k.Public, address, nonce)
	if err != nil {
		return Identity{}, err
	}

	signature, err := suite.Sign(k, message)
	if err != nil {
		return Identity{}, err
	}

	return Identity{
		Address:        address,
		Public:         k.Public,
		Signature:      signature,
		ValidatorNonce: nonce,
	}, nil
}

type Identity struct {
	ValidatorNonce uint32 `json:"validator_nonce"`
	Address        string `json:"address"`
	Public         []byte `json:"public"`
	Signature      []byte `json:"signature"`
}

// Verify checks the signature for a given identity is valid, if e.g. pulled from a remote file
func (i Identity) Verify(suite SigningScheme) error {
	m, err := digestFor(i.Public, i.Address, i.ValidatorNonce)
	if err != nil {
		return err
	}
	return suite.Verify(m, i.Public, i.Signature)
}

func digestFor(publicKey []byte, address string, validatorNonce uint32) ([]byte, error) {
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

	if err := binary.Write(buf, binary.BigEndian, validatorNonce); err != nil {
		return nil, err
	}

	out := sha256.New()
	if _, err := out.Write(buf.Bytes()); err != nil {
		return nil, err
	}
	return out.Sum(nil), nil
}
