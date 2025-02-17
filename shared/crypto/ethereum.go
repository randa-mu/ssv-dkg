package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ferranbt/fastssz/spectests"
	eth "github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/codec"
	"github.com/protolambda/ztyp/tree"
)

type DepositMessage struct {
	WithdrawalCredentials []byte
	Amount                uint64
	PublicKey             []byte
}

// DepositMessageSigningRoot is the message with domain that actually gets signed
func DepositMessageSigningRoot(data DepositMessage, forkVersion []byte) ([]byte, error) {
	m, err := DepositMessageRoot(data)
	if err != nil {
		return nil, err
	}

	if len(forkVersion) != 4 {
		return nil, fmt.Errorf("genesis fork version must be 4 bytes; got %d", len(forkVersion))
	}

	var gfk [4]byte
	copy(gfk[:], forkVersion)

	domain := append(eth.DOMAIN_DEPOSIT[:], forkVersion...)
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
	depositMessage := eth.DepositMessage{
		Pubkey:                pk,
		WithdrawalCredentials: wc,
		Amount:                eth.Gwei(data.Amount),
	}
	return hashToRoot(&depositMessage)
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
	depositData := eth.DepositData{
		Pubkey:                pk,
		WithdrawalCredentials: wc,
		Amount:                eth.Gwei(data.Amount),
		Signature:             sig,
	}

	return hashToRoot(&depositData)
}

func ValidatorNonceMessage(address []byte, validatorNonce uint32) ([]byte, error) {
	addr := FormatAddress(address)
	return []byte(fmt.Sprintf("%s:%d", addr, validatorNonce)), nil
}

func FormatAddress(address []byte) string {
	return common.BytesToAddress(address).String()
}

type HashToRootable interface {
	HashTreeRoot(hFn tree.HashFn) tree.Root
}

func hashToRoot(data HashToRootable) ([]byte, error) {
	root := data.HashTreeRoot(tree.GetHashFn())
	buf := bytes.Buffer{}
	writer := codec.NewEncodingWriter(&buf)
	if err := root.Serialize(writer); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
