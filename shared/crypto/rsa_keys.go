package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
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
	pk, err := parseRsaPublicKey(publicKey)
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

// parseRsaPublicKey will unmarshal any bytes that have been normalised using `NormalisePublicKeyBytes`
func parseRsaPublicKey(b []byte) (*rsa.PublicKey, error) {
	if len(b) == 0 {
		return nil, errors.New("public key was empty")
	}

	return x509.ParsePKCS1PublicKey(b)
}

// NormalisePublicKeyBytes takes bytes representing a public key from a variety of sources and transforms them
// into a format usable by the sidecar and other apps
func NormalisePublicKeyBytes(fileBytes []byte) ([]byte, error) {
	// if it's in pkcs1 format, just return it
	_, err := x509.ParsePKCS1PublicKey(fileBytes)
	if err == nil {
		return fileBytes, nil
	}

	// otherwise try unwrapping the PEM
	block, _ := pem.Decode(fileBytes)
	if block == nil {
		return nil, fmt.Errorf("could not decode the public key - not in PEM or PKCS1 format")
	}

	out, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PEM: %w", err)
	}

	// and try to parse the interior key as an RSA key
	parsed, ok := out.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to parse public key bytes wrapped in PEM: %w", err)
	}

	return x509.MarshalPKCS1PublicKey(parsed), nil
}
