package files

import (
	"encoding/hex"

	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
)

func CreateSignedDepositData(scheme crypto.ThresholdScheme, config api.SignatureConfig, output api.SigningOutput) api.SignedDepositData {
	var sig []byte
	hex.Encode(sig, output.DepositDataSignature)
	return api.SignedDepositData{
		UnsignedDepositData: config.DepositData,
		PubKey:              crypto.ExtractGroupPublicKey(scheme, output.GroupPublicPolynomial),
		Signature:           sig,
	}
}
