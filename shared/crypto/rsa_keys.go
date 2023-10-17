package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
)

type rsaSuite struct {
}

func NewRSASuite() rsaSuite {
	return rsaSuite{}
}

func (r rsaSuite) CreateKeypair() (Keypair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return Keypair{}, err
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	return Keypair{
		Private: privateKeyBytes,
		Public:  pubKeyBytes,
	}, nil
}

func (r rsaSuite) Sign(k Keypair, message []byte) ([]byte, error) {
	privateKey, err := x509.ParsePKCS1PrivateKey(k.Private)
	if err != nil {
		return nil, err
	}

	sha := sha256.New()
	sha.Write(message)
	digest := sha.Sum(nil)

	return privateKey.Sign(rand.Reader, digest, crypto.SHA256)
}

func (r rsaSuite) Verify(message []byte, publicKey []byte, signature []byte) error {
	pk, err := x509.ParsePKCS1PublicKey(publicKey)
	if err != nil {
		return err
	}

	sha := sha256.New()
	sha.Write(message)
	digest := sha.Sum(nil)

	return rsa.VerifyPKCS1v15(pk, crypto.SHA256, digest, signature)
}
