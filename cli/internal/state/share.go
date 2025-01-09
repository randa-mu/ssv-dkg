package state

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
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
	publicKey := hex.EncodeToString(signingOutput.GroupPublicKey)

	operators := make([]operator, len(signingOutput.OperatorShares))
	operatorIDs := make([]uint32, len(signingOutput.OperatorShares))
	var publicKeys []byte
	var encryptedShares []byte

	for i, share := range signingOutput.OperatorShares {
		operatorKey := make([]byte, base64.RawStdEncoding.EncodedLen(len(share.Identity.Public)))
		base64.RawStdEncoding.Encode(operatorKey, share.Identity.Public)
		operators[i] = operator{
			Id:          uint32(i),
			OperatorKey: operatorKey,
		}
		operatorIDs[i] = uint32(i)
		publicKeys = append(publicKeys, share.Identity.Public...)
		encryptedShares = append(encryptedShares, share.EncryptedShare...)
	}

	sharesData := append(append(signingOutput.ValidatorNonceSignature, publicKeys...), encryptedShares...)

	return KeyshareFile{
		Version:   KeyshareFileVersion,
		CreatedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Shares: []keyShare{
			{
				Data: data{
					OwnerNonce:   ownerConfig.ValidatorNonce,
					OwnerAddress: fmt.Sprintf("0x%s", hex.EncodeToString(ownerConfig.Address)),
					PublicKey:    publicKey,
					Operators:    operators,
				},
				Payload: payload{
					PublicKey:   publicKey,
					OperatorIDs: operatorIDs,
					SharesData:  fmt.Sprintf("0x%s", hex.EncodeToString(sharesData)),
				},
			},
		},
	}
}
