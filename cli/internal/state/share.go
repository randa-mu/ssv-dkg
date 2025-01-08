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
	publicKey := hex.EncodeToString(signingOutput.GroupPublicKey)

	operators := make([]operator, len(signingOutput.OperatorShares))
	operatorIDs := make([]uint32, len(signingOutput.OperatorShares))

	for i, share := range signingOutput.OperatorShares {
		operatorKey := make([]byte, base64.StdEncoding.EncodedLen(len(share.Identity.Public)))
		base64.StdEncoding.Encode(operatorKey, share.Identity.Public)
		operators[i] = operator{
			Id:          uint32(i),
			OperatorKey: operatorKey,
		}
		operatorIDs[i] = uint32(i)
	}

	return KeyshareFile{
		Version:   KeyshareFileVersion,
		CreatedAt: time.Now().UTC().String(),
		Shares: []keyShare{
			{
				Data: data{
					OwnerNonce:   ownerConfig.ValidatorNonce,
					OwnerAddress: hex.EncodeToString(ownerConfig.Address),
					PublicKey:    publicKey,
					Operators:    operators,
				},
				Payload: payload{
					PublicKey:   publicKey,
					OperatorIDs: operatorIDs,
					// TODO: work out how this is actually encoded from the encrypted sahres
					SharesData: "0xdeadbeefdeadbeef",
				},
			},
		},
	}
}
