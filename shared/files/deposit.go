package files

import (
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
)

func CreateSignedDepositData(scheme crypto.ThresholdScheme, config api.SignatureConfig, output api.SigningOutput) ([]api.SignedDepositData, error) {
	groupPublicKey := crypto.ExtractGroupPublicKey(scheme, output.GroupPublicPolynomial)
	// our wrapper types require jumping through this hoop
	var sig []byte
	sig = output.DepositDataSignature

	depositMessage := config.DepositData.IntoMessage(groupPublicKey)
	depositData := crypto.DepositData{
		WithdrawalCredentials: depositMessage.WithdrawalCredentials,
		Amount:                depositMessage.Amount,
		PublicKey:             depositMessage.PublicKey,
		Signature:             sig,
	}
	depositMessageRoot, err := crypto.DepositMessageRoot(depositMessage)
	if err != nil {
		return nil, err
	}

	depositDataRoot, err := crypto.DepositDataRoot(depositData)
	if err != nil {
		return nil, err
	}

	return []api.SignedDepositData{
		{
			WithdrawalCredentials: config.DepositData.WithdrawalCredentials,
			DepositMessageRoot:    depositMessageRoot,
			DepositDataRoot:       depositDataRoot,
			Amount:                config.DepositData.Amount,
			ForkVersion:           config.DepositData.ForkVersion,
			NetworkName:           config.DepositData.NetworkName,
			DepositCLIVersion:     config.DepositData.DepositCLIVersion,
			PubKey:                groupPublicKey,
			Signature:             sig,
		},
	}, nil
}
