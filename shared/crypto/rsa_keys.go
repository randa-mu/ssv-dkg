package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
)

type RsaSuite struct{}

func NewRSASuite() RsaSuite {
	return RsaSuite{}
}

func (r RsaSuite) CreateKeypair() (Keypair, error) {
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

func (r RsaSuite) Sign(k Keypair, message []byte) ([]byte, error) {
	privateKey, err := x509.ParsePKCS1PrivateKey(k.Private)
	if err != nil {
		return nil, err
	}

	sha := sha256.New()
	sha.Write(message)
	digest := sha.Sum(nil)

	return privateKey.Sign(rand.Reader, digest, crypto.SHA256)
}

func (r RsaSuite) Verify(message []byte, publicKey []byte, signature []byte) error {
	pk, err := x509.ParsePKCS1PublicKey(publicKey)
	if err != nil {
		return err
	}

	sha := sha256.New()
	sha.Write(message)
	digest := sha.Sum(nil)

	return rsa.VerifyPKCS1v15(pk, crypto.SHA256, digest, signature)
}

func (r RsaSuite) Encrypt(publicKey []byte, plaintext []byte) ([]byte, error) {
	pk, err := x509.ParsePKCS1PublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return rsa.EncryptPKCS1v15(rand.Reader, pk, plaintext)
}

func (r RsaSuite) Decrypt(privateKey []byte, ciphertext []byte) ([]byte, error) {
	sk, err := x509.ParsePKCS1PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptPKCS1v15(rand.Reader, sk, ciphertext)
}
