package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
)

type Keypair struct {
	Private []byte `json:"private"`
	Public  []byte `json:"public"`
}

func CreateKeypair() (Keypair, error) {
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

type Identity struct {
	Public    []byte `json:"public"`
	Address   string `json:"address"`
	Signature []byte `json:"signature"`
}

func (k Keypair) SelfSign(address string) (Identity, error) {
	privateKey, err := x509.ParsePKCS1PrivateKey(k.Private)
	if err != nil {
		return Identity{}, err
	}

	message := append(k.Public, []byte(address)...)
	sha := sha256.New()
	sha.Write(message)
	digest := sha.Sum(nil)

	signature, err := privateKey.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return Identity{}, err
	}

	return Identity{
		Address:   address,
		Public:    k.Public,
		Signature: signature,
	}, nil
}

func (k Keypair) Sign(message []byte) ([]byte, error) {
	privateKey, err := x509.ParsePKCS1PrivateKey(k.Private)
	if err != nil {
		return nil, err
	}

	sha := sha256.New()
	sha.Write(message)
	digest := sha.Sum(nil)

	return privateKey.Sign(rand.Reader, digest, crypto.SHA256)
}

func (i Identity) Verify() error {
	pk, err := x509.ParsePKCS1PublicKey(i.Public)
	if err != nil {
		return err
	}

	message := append(i.Public, []byte(i.Address)...)
	sha := sha256.New()
	sha.Write(message)
	digest := sha.Sum(nil)

	return rsa.VerifyPKCS1v15(pk, crypto.SHA256, digest, i.Signature)
}
