package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	ssz "github.com/ferranbt/fastssz"
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

func (d DepositMessage) AsETH() spectests.DepositMessage {
	var pk [48]byte
	var wc [32]byte
	copy(pk[:], d.PublicKey)
	copy(wc[:], d.WithdrawalCredentials)
	return spectests.DepositMessage{
		Pubkey:                d.PublicKey,
		WithdrawalCredentials: d.WithdrawalCredentials,
		Amount:                d.Amount,
	}
}

type ForkData struct {
	CurrentVersion        []byte `ssz-size:"4"`
	GenesisValidatorsRoot []byte `ssz-size:"32"`
}

// HashTreeRootWith ssz hashes the ForkData object with a hasher
func (f *ForkData) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'CurrentVersion'
	if size := len(f.CurrentVersion); size != 4 {
		err = ssz.ErrBytesLengthFn("ForkData.CurrentVersion", size, 4)
		return
	}
	hh.PutBytes(f.CurrentVersion[:])

	// Field (1) 'GenesisValidatorsRoot'
	if size := len(f.GenesisValidatorsRoot); size != 32 {
		err = ssz.ErrBytesLengthFn("ForkData.GenesisValidatorsRoot", size, 32)
		return
	}
	hh.PutBytes(f.GenesisValidatorsRoot[:])

	hh.Merkleize(indx)
	return
}

// HashTreeRoot ssz hashes the DepositMessage object
func (f *ForkData) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(f)
}

func (f *ForkData) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(f)
}

type SigningRoot struct {
	ObjectRoot []byte `ssz-size:"32"`
	DomainRoot []byte `ssz-size:"32"`
}

// HashTreeRootWith ssz hashes the ForkData object with a hasher
func (s *SigningRoot) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'ObjectRoot'
	if size := len(s.ObjectRoot); size != 32 {
		err = ssz.ErrBytesLengthFn("SigningRoot.ObjectRoot", size, 32)
		return
	}
	hh.PutBytes(s.ObjectRoot[:])

	// Field (1) 'DomainRoot'
	if size := len(s.DomainRoot); size != 32 {
		err = ssz.ErrBytesLengthFn("SigningRoot.DomainRoot", size, 32)
		return
	}
	hh.PutBytes(s.DomainRoot[:])

	hh.Merkleize(indx)
	return
}

// HashTreeRoot ssz hashes the DepositMessage object
func (s *SigningRoot) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(s)
}

func (s *SigningRoot) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(s)
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

	// seems the spectests was missing this one
	forkData := &ForkData{
		forkVersion,
		make([]byte, 32),
	}

	forkRoot, err := forkData.HashTreeRoot()
	if err != nil {
		panic(err)
	}

	domain := append(eth.DOMAIN_DEPOSIT[:], forkRoot[:28]...)

	// the spectests implementation somehow expects a domain of size 8 instead of 32!
	root := SigningRoot{
		m,
		domain,
	}

	rootHash, err := root.HashTreeRoot()
	return rootHash[:], err
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

	m := data.AsETH()
	b, err := m.HashTreeRoot()
	if err != nil {
		return nil, err
	}
	return b[:], nil
}

type DepositData struct {
	WithdrawalCredentials []byte
	Amount                uint64
	PublicKey             []byte
	Signature             []byte
}

func (d DepositData) AsETH() spectests.DepositData {
	var pk [48]byte
	var wc [32]byte
	//var sig [96]byte
	copy(pk[:], d.PublicKey)
	copy(wc[:], d.WithdrawalCredentials)
	//copy(sig[:], d.Signature)
	return spectests.DepositData{
		Pubkey:                pk,
		WithdrawalCredentials: wc,
		Amount:                d.Amount,
		Signature:             d.Signature,
		//Root:  // not sure what this should be?
	}
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

	m := data.AsETH()
	b, err := m.HashTreeRoot()
	if err != nil {
		return nil, err
	}
	return b[:], nil
}

func ValidatorNonceMessage(address []byte, validatorNonce uint32) ([]byte, error) {
	addr := FormatAddress(address)
	msg := []byte(fmt.Sprintf("%s:%d", addr, validatorNonce))

	return crypto.Keccak256(msg), nil
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
