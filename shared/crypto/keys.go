package crypto

import (
	"github.com/drand/kyber"
	"github.com/drand/kyber/share"
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
	SignWithPartial(private *share.PriShare, msg []byte) ([]byte, error)
	VerifyPartial(public *share.PubPoly, msg, sig []byte) error
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
func (k Keypair) SelfSign(suite SigningScheme, address string) (Identity, error) {
	message := append(k.Public, []byte(address)...)

	signature, err := suite.Sign(k, message)
	if err != nil {
		return Identity{}, err
	}

	return Identity{
		Address:   address,
		Public:    k.Public,
		Signature: signature,
	}, nil
}

type Identity struct {
	Address   string `json:"address"`
	Public    []byte `json:"public"`
	Signature []byte `json:"signature"`
}

// Verify checks the signature for a given identity is valid, if e.g. pulled from a remote file
func (i Identity) Verify(suite SigningScheme) error {
	m := append(i.Public, []byte(i.Address)...)
	return suite.Verify(m, i.Public, i.Signature)
}
