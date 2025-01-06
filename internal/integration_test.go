package internal

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/randa-mu/ssv-dkg/cli"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"github.com/randa-mu/ssv-dkg/sidecar"
)

func TestSuccessfulSigningAndResharing(t *testing.T) {
	ports := []uint{10001, 10002, 10003, 10004}
	startSidecars(t, ports)

	operators := fmap(ports, func(o uint) string {
		return fmt.Sprintf("http://127.0.0.1:%d", o)
	})

	depositData := createUnsignedDepositData()

	log := shared.QuietLogger{Quiet: false}
	address, err := hex.DecodeString("deadbeef")
	require.NoError(t, err)

	args := cli.SignatureConfig{
		Operators:   operators,
		DepositData: depositData,
		Owner: api.OwnerConfig{
			ValidatorNonce: 1,
			Address:        address,
		},
	}
	signingOutput, err := cli.Sign(args, log)
	require.NoError(t, err)
	require.NotEmpty(t, signingOutput)
	require.NotEmpty(t, signingOutput.DepositDataSignature)
	require.NotEmpty(t, signingOutput.PolynomialCommitments)
	require.NotEmpty(t, signingOutput.OperatorShares)

	signingOutput, err = cli.Reshare(operators, signingOutput, log)
	require.NoError(t, err)
	require.NotEmpty(t, signingOutput)
	require.NotEmpty(t, signingOutput.DepositDataSignature)
	require.NotEmpty(t, signingOutput.PolynomialCommitments)
	require.NotEmpty(t, signingOutput.OperatorShares)

	// reshare a second time with the same group just to confirm the polynomial commitments have been saved as expected
	signingOutput, err = cli.Reshare(operators, signingOutput, log)
	require.NoError(t, err)
	require.NotEmpty(t, signingOutput)
	require.NotEmpty(t, signingOutput.DepositDataSignature)
	require.NotEmpty(t, signingOutput.PolynomialCommitments)
	require.NotEmpty(t, signingOutput.OperatorShares)

	// reshare a third time with a slightly different group
	startSidecars(t, []uint{10005})
	operators = append(operators[0:3], "http://127.0.0.1:10005")
	signingOutput, err = cli.Reshare(operators, signingOutput, log)
	require.NoError(t, err)
	require.NotEmpty(t, signingOutput)
	require.NotEmpty(t, signingOutput.DepositDataSignature)
	require.NotEmpty(t, signingOutput.PolynomialCommitments)
	require.NotEmpty(t, signingOutput.OperatorShares)
}

func TestResharingNewNode(t *testing.T) {
	ports := []uint{10001, 10002, 10003, 10004}
	startSidecars(t, ports)

	operators := fmap(ports, func(o uint) string {
		return fmt.Sprintf("http://127.0.0.1:%d", o)
	})

	depositData := createUnsignedDepositData()

	log := shared.QuietLogger{Quiet: false}

	address, err := hex.DecodeString("deadbeef")
	require.NoError(t, err)
	args := cli.SignatureConfig{
		Operators:   operators,
		DepositData: depositData,
		Owner: api.OwnerConfig{
			ValidatorNonce: 0,
			Address:        address,
		},
	}
	signingOutput, err := cli.Sign(args, log)
	require.NoError(t, err)
	require.NotEmpty(t, signingOutput)
	require.NotEmpty(t, signingOutput.DepositDataSignature)
	require.NotEmpty(t, signingOutput.PolynomialCommitments)
	require.NotEmpty(t, signingOutput.OperatorShares)

	// reshare a third time with a slightly different group
	startSidecars(t, []uint{10006})
	operators = append(operators[0:3], "http://127.0.0.1:10006")
	signingOutput, err = cli.Reshare(operators, signingOutput, log)
	require.NoError(t, err)
	require.NotEmpty(t, signingOutput)
	require.NotEmpty(t, signingOutput.DepositDataSignature)
	require.NotEmpty(t, signingOutput.PolynomialCommitments)
	require.NotEmpty(t, signingOutput.OperatorShares)
}

func TestErroneousNodeOnStartup(t *testing.T) {
	ports := []uint{10011, 10012, 10013}
	startSidecars(t, ports)
	startErrorSidecars(t, []uint{10014}, ErrorStartingDKG{})

	operators := fmap(ports, func(o uint) string {
		return fmt.Sprintf("http://127.0.0.1:%d", o)
	})

	depositData := createUnsignedDepositData()
	address, err := hex.DecodeString("deadbeef")
	require.NoError(t, err)
	args := cli.SignatureConfig{
		Operators:   operators,
		DepositData: depositData,
		Owner: api.OwnerConfig{
			ValidatorNonce: 0,
			Address:        address,
		},
	}
	_, err = cli.Sign(args, shared.QuietLogger{Quiet: false})
	require.Error(t, err)
}

func TestErroneousNodeOnRunningDKG(t *testing.T) {
	ports := []uint{10021, 10022, 10023}
	startSidecars(t, ports)
	startErrorSidecars(t, []uint{10024}, ErrorDuringDKG{scheme: crypto.NewBLSSuite(), url: "http://127.0.0.1:10023"})

	operators := fmap(ports, func(o uint) string {
		return fmt.Sprintf("http://127.0.0.1:%d", o)
	})

	depositData := createUnsignedDepositData()
	address, err := hex.DecodeString("deadbeef")
	require.NoError(t, err)
	args := cli.SignatureConfig{
		Operators:   operators,
		DepositData: depositData,
		Owner: api.OwnerConfig{
			ValidatorNonce: 0,
			Address:        address,
		},
	}
	_, err = cli.Sign(args, shared.QuietLogger{Quiet: false})
	require.Error(t, err)
}

func startSidecars(t *testing.T, ports []uint) []sidecar.Daemon {
	out := make([]sidecar.Daemon, len(ports))
	for i, o := range ports {
		d := createDaemon(t, o)
		out[i] = d
		go func() {
			d.Start()
		}()
		err := awaitSidecarHealthy(o)
		if err != nil {
			t.Fatalf("error starting stub: %v", err)
		}
	}
	t.Cleanup(func() {
		for _, n := range out {
			n.Stop()
		}
	})
	return out
}

func startErrorSidecars(t *testing.T, ports []uint, errorCooordinator sidecar.DKGProtocol) []sidecar.Daemon {
	out := make([]sidecar.Daemon, len(ports))
	for i, o := range ports {
		d := createErrorDaemon(t, o, errorCooordinator)
		out[i] = d
		go func() {
			d.Start()
		}()
		err := awaitSidecarHealthy(o)
		if err != nil {
			t.Fatalf("error starting stub: %v", err)
		}
	}
	t.Cleanup(func() {
		for _, n := range out {
			n.Stop()
		}
	})
	return out
}

func createErrorDaemon(t *testing.T, port uint, errorCoordinator sidecar.DKGProtocol) sidecar.Daemon {
	stateDir := path.Join(t.TempDir(), strconv.Itoa(int(port)))
	err := sidecar.GenerateKey(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	ssvKeyPath := path.Join(stateDir, "pub.json")
	err = generateRSAKey(path.Join(stateDir, "pub.json"))
	if err != nil {
		t.Fatal(err)
	}
	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	_, err = sidecar.SignKey(url, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	d, err := sidecar.NewDaemonWithDKG(port, url, stateDir, errorCoordinator, ssvKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func createDaemon(t *testing.T, port uint) sidecar.Daemon {
	stateDir := path.Join(t.TempDir(), strconv.Itoa(int(port)))
	err := sidecar.GenerateKey(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	ssvKeyPath := path.Join(stateDir, "pub.json")
	err = generateRSAKey(ssvKeyPath)
	if err != nil {
		t.Fatal(err)
	}

	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	_, err = sidecar.SignKey(url, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	d, err := sidecar.NewDaemon(port, url, stateDir, ssvKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func fmap[T any, U any](arr []T, f func(T) U) []U {
	out := make([]U, len(arr))
	for i, j := range arr {
		out[i] = f(j)
	}
	return out
}

type healthCheck interface {
	Health() error
}

func awaitHealthy(h healthCheck) error {
	var err error
	for i := 0; i < 5; i++ {
		if err = h.Health(); err == nil {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return err
}

func awaitSidecarHealthy(port uint) error {
	c := api.NewSidecarClient(fmt.Sprintf("http://127.0.0.1:%d", port))
	return awaitHealthy(c)
}

func awaitStubHealthy(port uint) error {
	c := api.NewSsvClient(fmt.Sprintf("http://127.0.0.1:%d", port))
	return awaitHealthy(c)
}

func createUnsignedDepositData() api.UnsignedDepositData {
	return api.UnsignedDepositData{
		WithdrawalCredentials: []byte("hello worldhello worldhello worl"), // must be 32 bytes
		DepositDataRoot:       []byte("hello world"),
		DepositMessageRoot:    []byte("hello world"),
		Amount:                1,
		ForkVersion:           "somefork",
		NetworkName:           "somenetwork",
		DepositCLIVersion:     "somecli",
	}
}

type fileWithPublicKey struct {
	PublicKey []byte `json:"pubKey"`
}

func generateRSAKey(path string) error {
	suite := crypto.NewRSASuite()
	kp, err := suite.CreateKeypair()
	if err != nil {
		return err
	}

	file := fileWithPublicKey{
		PublicKey: kp.Public,
	}
	bytes, err := json.Marshal(file)
	if err != nil {
		return err
	}

	return os.WriteFile(path, bytes, 0o644)
}
