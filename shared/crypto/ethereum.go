package crypto

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ferranbt/fastssz/spectests"
	eth "github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/tree"
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

	domain, err := hex.DecodeString(fmt.Sprintf("03000000%s", forkVersion))
	if err != nil {
		return nil, err
	}
	root := spectests.SigningRoot{
		ObjectRoot: m,
		Domain:     domain,
	}
	return root.MarshalSSZ()
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

	var pk [48]byte
	var wc [32]byte

	copy(pk[:], data.PublicKey)
	copy(wc[:], data.WithdrawalCredentials)
	d := eth.DepositMessage{
		Pubkey:                pk,
		WithdrawalCredentials: wc,
		Amount:                eth.Gwei(data.Amount),
	}

	root := d.HashTreeRoot(tree.Hash)

	return root[:], nil
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

	var pk [48]byte
	var wc [32]byte
	var sig [96]byte

	copy(pk[:], data.PublicKey)
	copy(wc[:], data.WithdrawalCredentials)
	copy(sig[:], data.Signature)
	d := eth.DepositData{
		Pubkey:                pk,
		WithdrawalCredentials: wc,
		Amount:                eth.Gwei(data.Amount),
		Signature:             sig,
	}

	root := d.HashTreeRoot(tree.Hash)
	return root[:], nil
}

func ValidatorNonceMessage(address []byte, validatorNonce uint32) ([]byte, error) {
	addr := FormatAddress(address)
	return []byte(fmt.Sprintf("%s:%d", addr, validatorNonce)), nil
}

func FormatAddress(address []byte) string {
	return common.BytesToAddress(address).String()
}
