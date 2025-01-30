package files

import (
	"encoding/hex"

	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
)

func CreateSignedDepositData(scheme crypto.ThresholdScheme, config api.SignatureConfig, output api.SigningOutput) api.SignedDepositData {
	pk := crypto.ExtractGroupPublicKey(scheme, output.GroupPublicPolynomial)
	var sig []byte
	hex.Encode(sig, output.DepositDataSignature)
	return api.SignedDepositData{
		WithdrawalCredentials: config.DepositData.WithdrawalCredentials,
		DepositDataRoot:       config.DepositData.DepositDataRoot,
		DepositMessageRoot:    config.DepositData.DepositMessageRoot,
		Amount:                config.DepositData.Amount,
		ForkVersion:           config.DepositData.ForkVersion,
		NetworkName:           config.DepositData.NetworkName,
		DepositCLIVersion:     config.DepositData.DepositCLIVersion,
		PubKey:                pk,
		Signature:             sig,
	}
}
