package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
)

type RequiredDepositFields struct {
	WithdrawalCredentials []byte
	Amount                uint64
}

func DepositDataMessage(data RequiredDepositFields, groupPublicKey []byte) ([]byte, error) {
	if len(data.WithdrawalCredentials) != 32 {
		return nil, errors.New("withdrawal credentials must be 32 bytes; actual length " + strconv.Itoa(len(data.WithdrawalCredentials)))
	}

	if data.Amount <= 0 {
		return nil, errors.New("amount must be greater than zero")
	}

	if len(groupPublicKey) != 48 {
		return nil, errors.New("group public key must be 48 bytes long")
	}

	b := bytes.Buffer{}
	b.Write(groupPublicKey)
	b.Write(data.WithdrawalCredentials)
	err := binary.Write(&b, binary.BigEndian, data.Amount)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(b.Bytes())
	return hash[:], nil
}

func ValidatorNonceMessage(address []byte, validatorNonce uint32) ([]byte, error) {
	addr := FormatAddress(address)
	return []byte(fmt.Sprintf("%s:%d", addr, validatorNonce)), nil
}

func FormatAddress(address []byte) string {
	return common.BytesToAddress(address).String()
}
