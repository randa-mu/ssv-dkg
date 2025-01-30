package files

import (
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
)

func CreateSignedDepositData(scheme crypto.ThresholdScheme, config api.SignatureConfig, output api.SigningOutput) api.SignedDepositData {
	return api.SignedDepositData{
		UnsignedDepositData: config.DepositData,
		PubKey:              crypto.ExtractGroupPublicKey(scheme, output.GroupPublicPolynomial),
		Signature:           output.DepositDataSignature,
	}
}
