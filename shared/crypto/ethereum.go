package crypto

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/randa-mu/ssv-dkg/shared"
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

	return binary.BigEndian.AppendUint64(shared.Clone(data.WithdrawalCredentials), data.Amount), nil
}

func DepositDataMessage(data RequiredDepositFields, groupPublicKey []byte) ([]byte, error) {
	msg, err := PreDKGDepositDataMessage(data)
	if err != nil {
		return nil, err
	}
	return append(groupPublicKey, msg...), nil
}

func ValidatorNonceMessage(address []byte, validatorNonce uint32) ([]byte, error) {
	addr, err := FormatAddress(address)
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf("%s:%d", addr, validatorNonce)), nil
}

func FormatAddress(address []byte) (string, error) {
	ethAddress, err := common.NewMixedcaseAddressFromString(hex.EncodeToString(address))
	if err != nil {
		return "", err
	}
	return ethAddress.Address().Hex(), nil
}
