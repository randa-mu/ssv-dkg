package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
)

type DepositMessage struct {
	WithdrawalCredentials []byte
	Amount                uint64
	PublicKey             []byte
}

// DepositMessageSignatureMessage is the message with domain that actually gets signed
func DepositMessageSignatureMessage(data DepositMessage, forkVersion string) ([]byte, error) {
	m, err := DepositMessageRoot(data)
	if err != nil {
		return nil, err
	}
	return hashWithDomain(m, forkVersion)
}

// DepositMessageRoot is the merkle root included in the deposit data
func DepositMessageRoot(data DepositMessage) ([]byte, error) {
	if len(data.WithdrawalCredentials) != 32 {
		return nil, errors.New("withdrawal credentials must be 32 bytes; actual length " + strconv.Itoa(len(data.WithdrawalCredentials)))
	}

	if data.Amount <= 0 {
		return nil, errors.New("amount must be greater than zero")
	}

	if len(data.PublicKey) != 48 {
		return nil, errors.New("group public key must be 48 bytes long")
	}

	b := bytes.Buffer{}
	b.Write(data.PublicKey)
	b.Write(data.WithdrawalCredentials)
	b.Write(encodeUint64(data.Amount))

	hashedRoot := sha256.Sum256(b.Bytes())
	return hashedRoot[:], nil
}

func encodeUint64(i uint64) []byte {
	b := make([]byte, 8)
	for j := uint(0); j < 8; j++ {
		b[j] = byte(i >> (8 * j))
	}
	return b
}

type DepositData struct {
	WithdrawalCredentials []byte
	Amount                uint64
	PublicKey             []byte
	Signature             []byte
}

// DepositDataRoot is the merkle root included in the deposit data
func DepositDataRoot(data DepositData) ([]byte, error) {
	if len(data.WithdrawalCredentials) != 32 {
		return nil, errors.New("withdrawal credentials must be 32 bytes; actual length " + strconv.Itoa(len(data.WithdrawalCredentials)))
	}

	if data.Amount <= 0 {
		return nil, errors.New("amount must be greater than zero")
	}

	if len(data.PublicKey) != 48 {
		return nil, errors.New("group public key must be 48 bytes long")
	}

	if len(data.Signature) != 96 {
		return nil, errors.New("signature must be 96 bytes long")
	}

	b := bytes.Buffer{}
	b.Write(data.PublicKey)
	b.Write(data.WithdrawalCredentials)
	b.Write(encodeUint64(data.Amount))
	b.Write(data.Signature)

	hash := sha256.Sum256(b.Bytes())
	return hash[:], nil
}

func hashWithDomain(b []byte, forkVersion string) ([]byte, error) {
	domain, err := computeDomain(forkVersion)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(append(b[:], domain...))
	return hash[:], nil
}

func computeDomain(forkVersion string) ([]byte, error) {
	domainDeposit := "03000000"
	return hex.DecodeString(fmt.Sprintf("%s%s00000000", domainDeposit, forkVersion))
}

func ValidatorNonceMessage(address []byte, validatorNonce uint32) ([]byte, error) {
	addr := FormatAddress(address)
	return []byte(fmt.Sprintf("%s:%d", addr, validatorNonce)), nil
}

func FormatAddress(address []byte) string {
	return common.BytesToAddress(address).String()
}
