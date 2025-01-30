package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
)

type RequiredDepositFields struct {
	WithdrawalCredentials []byte
	Amount                uint64
}

func DepositDataMessage(data RequiredDepositFields, forkVersion string, groupPublicKey []byte) ([]byte, error) {
	if len(data.WithdrawalCredentials) != 32 {
		return nil, errors.New("withdrawal credentials must be 32 bytes; actual length " + strconv.Itoa(len(data.WithdrawalCredentials)))
	}

	if data.Amount <= 0 {
		return nil, errors.New("amount must be greater than zero")
	}

	if len(groupPublicKey) != 48 {
		return nil, errors.New("group public key must be 48 bytes long")
	}

	treeRoot := bytes.Buffer{}
	treeRoot.Write(groupPublicKey)
	treeRoot.Write(data.WithdrawalCredentials)
	err := binary.Write(&treeRoot, binary.BigEndian, data.Amount)
	if err != nil {
		return nil, err
	}

	hashTreeRoot := sha256.Sum256(treeRoot.Bytes())

	b := bytes.Buffer{}
	b.Write(hashTreeRoot[:])

	domain, err := computeDomain(forkVersion)
	if err != nil {
		return nil, err
	}
	b.Write(domain)
	finalHash := sha256.Sum256(b.Bytes())
	return finalHash[:], nil
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
