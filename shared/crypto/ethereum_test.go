package crypto

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/require"
	types "github.com/wealdtech/go-eth2-types/v2"
)

type DepositDataCLI struct {
	PubKey                string `json:"pubkey"`
	WithdrawalCredentials string `json:"withdrawal_credentials"`
	Amount                uint64 `json:"amount"`
	Signature             string `json:"signature"`
	DepositMessageRoot    string `json:"deposit_message_root"`
	DepositDataRoot       string `json:"deposit_data_root"`
	ForkVersion           string `json:"fork_version"`
	NetworkName           string `json:"network_name"`
	DepositCliVersion     string `json:"deposit_cli_version"`
}

func TestDepositDataRoot(t *testing.T) {
	inputs := []string{
		`{
			"pubkey": "85a84321189579ec2a20138f8ee11a2192285cf81012c4b375afd3817b33b0a10695e0f9c74c8db6b3fe79cabc51ea8e",
			"withdrawal_credentials": "01000000000000000000000081592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"amount": 32000000000,
			"signature": "a4510deacb8815aaec7f3f877287c45beb4a0b96dbbd7b72561b19d58393c417386d4d529e9809eb8a308459ee733de018e32dd48d66e03c47bcdb86bec389fa10a852bf0a3efa562f33697bead475dbf73880c000bc7f92da0daad4860fdd26",
			"deposit_message_root": "e9ea570d92bb1d576cdc30fd93e2b6b8e2d5f08225de469111bb4e19938706ad",
			"deposit_data_root": "cb466425c0721700bfbbed913d0008077aedbfeac85e9f8eaace91ef487d30f5",
			"fork_version": "01017000",
			"network_name": "holesky",
			"deposit_cli_version": "2.7.0"
		}`,
		`{"pubkey":"865d74c82589eb0f3d954af56cc9b5820b1fb371f27d49ed931d7f707f02f3ffb943064a355bc289aa251ff0f7cee28f","withdrawal_credentials":"0100000000000000000000005cc0dde14e7256340cc820415a6022a7d1c93a35","amount":32000000000,"signature":"a3d1dba36a40d1295637ccc538fe6ed71c078847613374cbbe18b3f5c1be0d82e8d05bc172c3e503b529336b8ef6ba9d0c6a0502f20e09039317d3586bf2d710f5c6ad34ced4e96700bcd2cae2fb643f7059308da14768734c5a83bd3b714e0f","deposit_message_root":"179889e9fe576c14e54781c80470988a1ae30dcf5aff420b229cbc98f9e5bad5","deposit_data_root":"00fff3ec0d7692d518d18a2057ca7f0616f5bb249690341931493aaed5fba7b3","fork_version":"01017000","network_name":"holesky","deposit_cli_version":"2.7.0"}`,
	}

	for i, input := range inputs {
		t.Run(fmt.Sprintf("valid-deposit-input-%d", i), func(t *testing.T) {
			d := new(DepositDataCLI)
			err := json.Unmarshal([]byte(input), d)
			if err != nil {
				t.Fatal("unmarshal error", "err", err)
			}

			if err := verifyDepositRoots(t, d); err != nil {
				t.Fatal("verify error", "err", err)
			}
		})
	}

}

func TheirRoot(data DepositData, genesisForkVersion []byte) ([]byte, error) {
	var pk [48]byte
	var wc [32]byte
	var sig [96]byte

	copy(pk[:], data.PublicKey)
	copy(wc[:], data.WithdrawalCredentials)
	copy(sig[:], data.Signature)

	// using phase0:
	dd := &phase0.DepositMessage{
		PublicKey:             pk,
		Amount:                phase0.Gwei(data.Amount),
		WithdrawalCredentials: wc[:],
	}

	// Compute DepositMessage root
	depositMsgRoot, err := dd.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("depositMsgRoot error: %w", err)
	}

	fmt.Printf("their depositMsgRoot: %x\n", depositMsgRoot)
	ourRoot, err := DepositDataRoot(data)
	if err != nil {
		return nil, err
	}
	fmt.Printf("our depositMsgRoot: %x\n", ourRoot)

	domain, err := types.ComputeDomain(types.DomainDeposit, genesisForkVersion[:], types.ZeroGenesisValidatorsRoot)
	if err != nil {
		return nil, fmt.Errorf("ComputeDomain error: %w", err)
	}

	container := &phase0.SigningData{
		ObjectRoot: depositMsgRoot,
		Domain:     phase0.Domain(domain),
	}
	signingRoot, err := container.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("HashTreeRoot error: %w", err)
	}

	fmt.Printf("our buggy root: 0x%x\n", ourRoot)
	fmt.Printf("phase0 ok root: 0x%x\n", signingRoot)

	return signingRoot[:], nil
}

func verifyDepositRoots(t *testing.T, d *DepositDataCLI) error {
	pubKey, err := hex.DecodeString(d.PubKey)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}
	t.Logf("pubkey: %x", pubKey)
	withdrCreds, err := hex.DecodeString(d.WithdrawalCredentials)
	if err != nil {
		return fmt.Errorf("failed to decode withdrawal credentials: %w", err)
	}
	t.Logf("withdrawal credentials: %x", withdrCreds)
	sig, err := hex.DecodeString(d.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}
	t.Logf("signature: %x", sig)
	fork, err := hex.DecodeString(d.ForkVersion)
	if err != nil {
		return fmt.Errorf("failed to decode fork version: %w", err)
	}
	t.Logf("fork version: %x", fork)
	if len(fork) != 4 {
		return fmt.Errorf("fork version has wrong length")
	}

	depositData := &phase0.DepositData{
		PublicKey:             phase0.BLSPubKey(pubKey),
		WithdrawalCredentials: withdrCreds,
		Amount:                phase0.Gwei(d.Amount),
		Signature:             phase0.BLSSignature(sig),
	}

	// HERE CHANGE TheirRoot to use your own code: it won't pass
	signingRoot, err := TheirRoot(DepositData{
		PublicKey:             depositData.PublicKey[:],
		Amount:                uint64(depositData.Amount),
		WithdrawalCredentials: depositData.WithdrawalCredentials,
		Signature:             depositData.Signature[:],
	}, fork)

	if err != nil {
		return fmt.Errorf("failed to compute signing root: %s", err)
	}

	suite := NewBLSSuite()
	require.NoError(t, suite.VerifyRaw(signingRoot[:], depositData.PublicKey[:], depositData.Signature[:]))
	return nil
}
