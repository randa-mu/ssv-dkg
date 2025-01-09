package state

import (
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/randa-mu/ssv-dkg/shared/api"
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
func CreateKeyshareFile(ownerConfig api.OwnerConfig, signingOutput api.SigningOutput) KeyshareFile {
	operators := make([]operator, len(signingOutput.OperatorShares))
	operatorIDs := make([]uint32, len(signingOutput.OperatorShares))
	var publicKeys []byte
	var encryptedShares []byte

	for i, share := range signingOutput.OperatorShares {
		operators[i] = createOperatorFromShare(share)
		operatorIDs[i] = share.Identity.OperatorID
		publicKeys = append(publicKeys, share.Identity.Public...)
		encryptedShares = append(encryptedShares, share.EncryptedShare...)
	}

	return KeyshareFile{
		Version:   KeyshareFileVersion,
		CreatedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Shares: []keyShare{
			{
				Data: data{
					OwnerNonce:   ownerConfig.ValidatorNonce,
					OwnerAddress: hex.EncodeToString(ownerConfig.Address),
					PublicKey:    hex.EncodeToString(signingOutput.GroupPublicKey),
					Operators:    operators,
				},
				Payload: payload{
					PublicKey:   hex.EncodeToString(signingOutput.GroupPublicKey),
					OperatorIDs: operatorIDs,
					SharesData:  createSharesData(signingOutput, publicKeys, encryptedShares),
				},
			},
		},
	}
}

// createOperatorFromShare creates the operator with base64 public keys, while everything else is hex
func createOperatorFromShare(share api.OperatorShare) operator {
	operatorKey := make([]byte, base64.RawStdEncoding.EncodedLen(len(share.Identity.Public)))
	base64.RawStdEncoding.Encode(operatorKey, share.Identity.Public)
	return operator{
		Id:          share.Identity.OperatorID,
		OperatorKey: operatorKey,
	}
}

// createSharesData combines the validator nonce signature with the public keys in order then the encrypted shares in order
func createSharesData(signingOutput api.SigningOutput, publicKeys []byte, encryptedShares []byte) string {
	return hex.EncodeToString(append(append(signingOutput.ValidatorNonceSignature, publicKeys...), encryptedShares...))
}
