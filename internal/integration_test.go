package internal

import (
	"fmt"
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
	"github.com/randa-mu/ssv-dkg/tools/stub"
)

func TestSuccessfulSigningAndResharing(t *testing.T) {
	var stubPort uint = 10000
	startStubSSVNode(t, stubPort)

	ports := []uint{10001, 10002, 10003, 10004}
	startSidecars(t, ports, stubPort)

	operators := fmap(ports, func(o uint) string {
		return fmt.Sprintf("http://127.0.0.1:%d", o)
	})

	depositData := createUnsignedDepositData()

	log := shared.QuietLogger{Quiet: false}
	signingOutput, err := cli.Sign(operators, depositData, 1, log)
	require.NoError(t, err)
	require.NotEmpty(t, signingOutput)
	require.NotEmpty(t, signingOutput.GroupSignature)
	require.NotEmpty(t, signingOutput.PolynomialCommitments)
	require.NotEmpty(t, signingOutput.OperatorShares)

	signingOutput, err = cli.Reshare(operators, signingOutput, log)
	require.NoError(t, err)
	require.NotEmpty(t, signingOutput)
	require.NotEmpty(t, signingOutput.GroupSignature)
	require.NotEmpty(t, signingOutput.PolynomialCommitments)
	require.NotEmpty(t, signingOutput.OperatorShares)

	// reshare a second time with the same group just to confirm the polynomial commitments have been saved as expected
	signingOutput, err = cli.Reshare(operators, signingOutput, log)
	require.NoError(t, err)
	require.NotEmpty(t, signingOutput)
	require.NotEmpty(t, signingOutput.GroupSignature)
	require.NotEmpty(t, signingOutput.PolynomialCommitments)
	require.NotEmpty(t, signingOutput.OperatorShares)

	// reshare a third time with a slightly different group
	startSidecars(t, []uint{10005}, stubPort)
	operators = append(operators[0:3], "http://127.0.0.1:10005")
	signingOutput, err = cli.Reshare(operators, signingOutput, log)
	require.NoError(t, err)
	require.NotEmpty(t, signingOutput)
	require.NotEmpty(t, signingOutput.GroupSignature)
	require.NotEmpty(t, signingOutput.PolynomialCommitments)
	require.NotEmpty(t, signingOutput.OperatorShares)
}

func TestResharingNewNode(t *testing.T) {
	var stubPort uint = 10000
	startStubSSVNode(t, stubPort)

	ports := []uint{10001, 10002, 10003, 10004}
	startSidecars(t, ports, stubPort)

	operators := fmap(ports, func(o uint) string {
		return fmt.Sprintf("http://127.0.0.1:%d", o)
	})

	depositData := createUnsignedDepositData()

	log := shared.QuietLogger{Quiet: false}
	signingOutput, err := cli.Sign(operators, depositData, 0, log)
	require.NoError(t, err)
	require.NotEmpty(t, signingOutput)
	require.NotEmpty(t, signingOutput.GroupSignature)
	require.NotEmpty(t, signingOutput.PolynomialCommitments)
	require.NotEmpty(t, signingOutput.OperatorShares)

	// reshare a third time with a slightly different group
	startSidecars(t, []uint{10006}, stubPort)
	operators = append(operators[0:3], "http://127.0.0.1:10006")
	signingOutput, err = cli.Reshare(operators, signingOutput, log)
	require.NoError(t, err)
	require.NotEmpty(t, signingOutput)
	require.NotEmpty(t, signingOutput.GroupSignature)
	require.NotEmpty(t, signingOutput.PolynomialCommitments)
	require.NotEmpty(t, signingOutput.OperatorShares)
}

func TestErroneousNodeOnStartup(t *testing.T) {
	var stubPort uint = 10010
	startStubSSVNode(t, stubPort)

	ports := []uint{10011, 10012, 10013}
	startSidecars(t, ports, stubPort)
	startErrorSidecars(t, []uint{10014}, stubPort, ErrorStartingDKG{})

	operators := fmap(ports, func(o uint) string {
		return fmt.Sprintf("http://127.0.0.1:%d", o)
	})

	depositData := createUnsignedDepositData()

	_, err := cli.Sign(operators, depositData, 0, shared.QuietLogger{Quiet: false})
	require.Error(t, err)
}

func TestErroneousNodeOnRunningDKG(t *testing.T) {
	var stubPort uint = 10020
	startStubSSVNode(t, stubPort)

	ports := []uint{10021, 10022, 10023}
	startSidecars(t, ports, stubPort)
	startErrorSidecars(t, []uint{10024}, stubPort, ErrorDuringDKG{scheme: crypto.NewBLSSuite(), url: "http://127.0.0.1:10023"})

	operators := fmap(ports, func(o uint) string {
		return fmt.Sprintf("http://127.0.0.1:%d", o)
	})

	depositData := createUnsignedDepositData()

	_, err := cli.Sign(operators, depositData, 0, shared.QuietLogger{Quiet: false})
	require.Error(t, err)
}

func startStubSSVNode(t *testing.T, ssvPort uint) {
	stop := stub.StartStub(ssvPort)
	t.Cleanup(stop)
	err := awaitStubHealthy(ssvPort)
	if err != nil {
		t.Fatalf("error starting SSV stub: %v", err)
	}
}

func startSidecars(t *testing.T, ports []uint, ssvPort uint) []sidecar.Daemon {
	out := make([]sidecar.Daemon, len(ports))
	for i, o := range ports {
		d := createDaemon(t, o, ssvPort)
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

func startErrorSidecars(t *testing.T, ports []uint, ssvPort uint, errorCooordinator sidecar.DKGProtocol) []sidecar.Daemon {
	out := make([]sidecar.Daemon, len(ports))
	for i, o := range ports {
		d := createErrorDaemon(t, o, ssvPort, errorCooordinator)
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

func createErrorDaemon(t *testing.T, port uint, ssvPort uint, errorCoordinator sidecar.DKGProtocol) sidecar.Daemon {
	stateDir := path.Join(t.TempDir(), strconv.Itoa(int(port)))
	err := sidecar.GenerateKey(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	_, err = sidecar.SignKey(url, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	ssvURL := fmt.Sprintf("http://127.0.0.1:%d", ssvPort)
	d, err := sidecar.NewDaemonWithDKG(port, url, ssvURL, stateDir, errorCoordinator)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func createDaemon(t *testing.T, port uint, ssvPort uint) sidecar.Daemon {
	stateDir := path.Join(t.TempDir(), strconv.Itoa(int(port)))
	err := sidecar.GenerateKey(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	_, err = sidecar.SignKey(url, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	ssvURL := fmt.Sprintf("http://127.0.0.1:%d", ssvPort)
	d, err := sidecar.NewDaemon(port, url, ssvURL, stateDir)
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
