package state

import (
	"fmt"
	"slices"
	"time"

	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
)

const KeyshareFileVersion = "v0.0.1"

type KeyshareFile struct {
	Version   string     `json:"version"`
	CreatedAt string     `json:"createdAt"`
	Shares    []keyShare `json:"shares"`
}

type keyShare struct {
	Data    data    `json:"data"`
	Payload payload `json:"payload"`
}

type data struct {
	OwnerNonce   uint32     `json:"ownerNonce"`
	OwnerAddress string     `json:"ownerAddress"`
	PublicKey    string     `json:"publicKey"`
	Operators    []operator `json:"operators"`
}

type operator struct {
	Id          uint32 `json:"id"`
	OperatorKey []byte `json:"operatorKey"`
}

type payload struct {
	PublicKey   string   `json:"publicKey"`
	OperatorIDs []uint32 `json:"operatorIds"`
	SharesData  string   `json:"sharesData"`
}

// CreateKeyshareFile takes output from the DKG/signing and creates the keyshare file required
// to register a validator cluster using the SSV portal
func CreateKeyshareFile(ownerConfig api.OwnerConfig, signingOutput api.SigningOutput, client api.SsvClient) (KeyshareFile, error) {
	ethAddress, err := crypto.FormatAddress(ownerConfig.Address)
	if err != nil {
		return KeyshareFile{}, fmt.Errorf("error formatting eth address: %v", err)
	}

	operators := make([]operator, len(signingOutput.OperatorShares))
	operatorIDs := make([]uint32, len(signingOutput.OperatorShares))
	var publicKeys []byte
	var encryptedShares []byte

	// first we sort the operator shares because that's how the SSV key tool does it
	sortedOperatorShares := signingOutput.OperatorShares
	slices.SortStableFunc(sortedOperatorShares, func(a, b api.OperatorShare) int {
		return int(a.Identity.OperatorID - b.Identity.OperatorID)
	})

	// then we extract all the relevant bits for each share
	for i, share := range sortedOperatorShares {
		operatorIDs[i] = share.Identity.OperatorID
		publicKeys = append(publicKeys, share.Identity.Public...)
		encryptedShares = append(encryptedShares, share.EncryptedShare...)
		res, err := client.FetchPublicKeyFromSsv(share.Identity.OperatorID)
		if err != nil {
			return KeyshareFile{}, fmt.Errorf("error fetching operator public key for %d: %v", share.Identity.OperatorID, err)
		}
		operators[i] = createOperatorFromShare(share, res.PublicKey)
	}

	scheme := crypto.NewBLSSuite()
	// the group public key is the 0th point on the polynomial
	groupPublicKey := prefixedHex(signingOutput.GroupPublicPolynomial[0:scheme.KeyGroup().PointLen()])

	return KeyshareFile{
		Version:   KeyshareFileVersion,
		CreatedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Shares: []keyShare{
			{
				Data: data{
					OwnerNonce:   ownerConfig.ValidatorNonce,
					OwnerAddress: ethAddress,
					PublicKey:    groupPublicKey,
					Operators:    operators,
				},
				Payload: payload{
					PublicKey:   groupPublicKey,
					OperatorIDs: operatorIDs,
					SharesData:  createSharesData(signingOutput, publicKeys, encryptedShares),
				},
			},
		},
	}, nil
}

// createOperatorFromShare creates the operator with base64 public keys, while everything else is hex
func createOperatorFromShare(share api.OperatorShare, ssvPublicKey []byte) operator {
	return operator{
		Id:          share.Identity.OperatorID,
		OperatorKey: ssvPublicKey,
	}
}

// createSharesData combines the validator nonce signature with the public keys in order then the encrypted shares in order
func createSharesData(signingOutput api.SigningOutput, publicKeys []byte, encryptedShares []byte) string {
	concatenatedBytes := append(append(signingOutput.ValidatorNonceSignature, publicKeys...), encryptedShares...)
	return prefixedHex(concatenatedBytes)
}

// prefixedHex encodes as hex but with the `0x` prefix
func prefixedHex(in []byte) string {
	return fmt.Sprintf("0x%x", in)
}
