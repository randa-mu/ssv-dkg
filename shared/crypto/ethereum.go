package crypto

import (
	"encoding/binary"
	"errors"
	"strconv"
)

type RequiredDepositFields struct {
	WithdrawalCredentials []byte
	Amount                uint64
}

func PreDKGDepositDataMessage(data RequiredDepositFields) ([]byte, error) {
	if len(data.WithdrawalCredentials) != 32 {
		return nil, errors.New("withdrawal credentials must be 32 bytes; actual length " + strconv.Itoa(len(data.WithdrawalCredentials)))
	}
	if data.Amount == 0 {
		return nil, errors.New("amount must be greater than zero")
	}

	return binary.BigEndian.AppendUint64(data.WithdrawalCredentials, data.Amount), nil
}

func DepositDataMessage(data RequiredDepositFields, publicKey []byte) ([]byte, error) {
	msg, err := PreDKGDepositDataMessage(data)
	if err != nil {
		return nil, err
	}
	return append(publicKey, msg...), nil
}

func ValidatorNonceMessage(nonce uint32) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint32(out, nonce)
	return out
}
