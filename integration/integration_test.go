package integration

import (
	"fmt"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/randa-mu/ssv-dkg/cli"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"github.com/randa-mu/ssv-dkg/sidecar"
	"github.com/randa-mu/ssv-dkg/tools/stub"
	"github.com/stretchr/testify/require"
)

func TestSuccessfulSigningAndResharing(t *testing.T) {
	var stubPort uint = 10000
	startStubSSVNode(t, stubPort)

	ports := []uint{10001, 10002, 10003}
	startSidecars(t, ports, stubPort)

	operators := fmap(ports, func(o uint) string {
		return fmt.Sprintf("%d,http://127.0.0.1:%d", o, o)
	})

	depositData := []byte("hello world")

	log := shared.QuietLogger{Quiet: false}
	signingOutput, err := cli.Sign(operators, depositData, log)
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
	startSidecars(t, []uint{10004}, stubPort)
	operators = append(operators[0:2], "10004,http://127.0.0.1:10004")
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

	ports := []uint{10001, 10002, 10003}
	startSidecars(t, ports, stubPort)

	operators := fmap(ports, func(o uint) string {
		return fmt.Sprintf("%d,http://127.0.0.1:%d", o, o)
	})

	depositData := []byte("hello world")

	log := shared.QuietLogger{Quiet: false}
	signingOutput, err := cli.Sign(operators, depositData, log)
	require.NoError(t, err)
	require.NotEmpty(t, signingOutput)
	require.NotEmpty(t, signingOutput.GroupSignature)
	require.NotEmpty(t, signingOutput.PolynomialCommitments)
	require.NotEmpty(t, signingOutput.OperatorShares)

	// reshare a third time with a slightly different group
	startSidecars(t, []uint{10004}, stubPort)
	operators = append(operators[0:2], "10004,http://127.0.0.1:10004")
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

	ports := []uint{10011, 10012}
	startSidecars(t, ports, stubPort)
	startErrorSidecars(t, []uint{10013}, stubPort, ErrorStartingDKG{})

	operators := fmap(append(ports, 10013), func(o uint) string {
		return fmt.Sprintf("%d,http://127.0.0.1:%d", o, o)
	})

	depositData := []byte("hello world")

	_, err := cli.Sign(operators, depositData, shared.QuietLogger{Quiet: false})
	require.Error(t, err)
}

func TestErroneousNodeOnRunningDKG(t *testing.T) {
	var stubPort uint = 10020
	startStubSSVNode(t, stubPort)

	ports := []uint{10021, 10022}
	startSidecars(t, ports, stubPort)
	startErrorSidecars(t, []uint{10023}, stubPort, ErrorDuringDKG{scheme: crypto.NewBLSSuite(), url: "http://127.0.0.1:10023"})

	operators := fmap(append(ports, 10023), func(o uint) string {
		return fmt.Sprintf("%d,http://127.0.0.1:%d", o, o)
	})

	depositData := []byte("hello world")

	_, err := cli.Sign(operators, depositData, shared.QuietLogger{Quiet: false})
	require.Error(t, err)
}

func startStubSSVNode(t *testing.T, ssvPort uint) {
	stop := stub.StartStub(ssvPort)
	t.Cleanup(stop)
	err := awaitHealthy(ssvPort)
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
		err := awaitHealthy(o)
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
		err := awaitHealthy(o)
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
	_, err = sidecar.SignKey(url, 1, stateDir)
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
	_, err = sidecar.SignKey(url, uint32(port), stateDir)
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

func awaitHealthy(port uint) error {
	c := api.NewSidecarClient(fmt.Sprintf("http://127.0.0.1:%d", port))
	var err error
	for i := 0; i < 5; i++ {
		if err = c.Health(); err == nil {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return err
}
