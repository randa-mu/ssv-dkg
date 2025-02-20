package internal

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/randa-mu/ssv-dkg/cli"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"github.com/randa-mu/ssv-dkg/shared/files"
	"github.com/randa-mu/ssv-dkg/sidecar"
	"github.com/stretchr/testify/require"
)

// TestPrintHolesky runs a DKG and prints out the resulting SSV file for use in testing in holesky
func TestPrintHolesky(t *testing.T) {
	ownerAddress, err := hex.DecodeString("17B3cAb3cD7502C6b85ed2E11Fd5988AF76Cdd32")
	validatorNonce := uint32(7)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		d := createHoleskyDaemon(t, i+1)
		d.Start()
	}
	time.Sleep(2 * time.Second)

	config := api.SignatureConfig{
		Operators: []string{
			"http://127.0.0.1:8881",
			"http://127.0.0.1:8882",
			"http://127.0.0.1:8883",
			"http://127.0.0.1:8884",
		},
		DepositData: depositData(t),
		Owner: api.OwnerConfig{
			Address:        ownerAddress,
			ValidatorNonce: validatorNonce,
		},
		SsvClient: api.HoleskySsvClient(),
	}
	res, err := cli.Sign(config, shared.QuietLogger{Quiet: false})
	require.NoError(t, err)

	file, err := files.CreateKeyshareFile(config.Owner, res, config.SsvClient)
	require.NoError(t, err)

	data, err := hex.DecodeString(file.Shares[0].Payload.SharesData[2:])
	require.NoError(t, err)

	suite := crypto.NewBLSSuite()
	sigLength := suite.KeyGroup().PointLen() * 2
	groupSig := data[0:sigLength]
	pk, err := hex.DecodeString(file.Shares[0].Data.PublicKey[2:])
	require.NoError(t, err)
	m, err := crypto.ValidatorNonceMessage(ownerAddress, validatorNonce)
	require.NoError(t, err)
	require.NoError(t, suite.Verify(m, pk, groupSig))

	bytes, err := json.Marshal(file)
	require.NoError(t, err)

	fmt.Println(string(bytes))
}

func createHoleskyDaemon(t *testing.T, index int) sidecar.Daemon {
	port, err := strconv.Atoi(fmt.Sprintf("888%d", index))
	if err != nil {
		t.Fatal(err)
	}

	stateDir := path.Join(t.TempDir(), strconv.Itoa(port))
	err = sidecar.GenerateKey(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	url := fmt.Sprintf("http://127.0.0.1:888%d", index)
	_, err = sidecar.SignKey(url, stateDir, uint32(port))
	if err != nil {
		t.Fatal(err)
	}

	keyPath := fmt.Sprintf("encrypted_private_key%d.json", index)
	operatorId := 1450 + index
	d, err := sidecar.NewDaemon(uint(port), url, stateDir, keyPath, uint32(operatorId))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func depositData(t *testing.T) api.UnsignedDepositData {
	j := `{
		"withdrawal_credentials":"01000000000000000000000017b3cab3cd7502c6b85ed2e11fd5988af76cdd32",
		"amount":32000000000,
		"fork_version":"01017000",
		"network_name":"holesky",
		"deposit_cli_version": "2.8.0"
	}`
	var d api.UnsignedDepositData
	if err := json.Unmarshal([]byte(j), &d); err != nil {
		t.Fatal(err)
	}
	return d
}
