package integration

import (
	"fmt"
	"github.com/randa-mu/ssv-dkg/cli"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"github.com/randa-mu/ssv-dkg/sidecar"
	"github.com/randa-mu/ssv-dkg/sidecar/dkg"
	"github.com/randa-mu/ssv-dkg/tools/stub"
	"github.com/stretchr/testify/require"
	"path"
	"strconv"
	"testing"
	"time"
)

func TestSuccessfulSigning(t *testing.T) {
	var stubPort uint = 10000
	startStubSSVNode(t, stubPort)

	ports := []uint{10001, 10002, 10003}
	startSidecars(t, ports, stubPort)

	operators := fmap(ports, func(o uint) string {
		return fmt.Sprintf("http://localhost:%d", o)
	})

	depositData := []byte("hello world")

	responses, err := cli.Sign(operators, depositData, shared.QuietLogger{Quiet: false})
	require.NoError(t, err)
	require.Equal(t, len(responses), len(ports))
}

func TestErroneousNodeOnStartup(t *testing.T) {
	var stubPort uint = 10010
	startStubSSVNode(t, stubPort)

	ports := []uint{10011, 10012}
	startSidecars(t, ports, stubPort)
	startErrorSidecars(t, []uint{10013}, stubPort, ErrorStartingDKG{})

	operators := fmap(append(ports, 10013), func(o uint) string {
		return fmt.Sprintf("http://localhost:%d", o)
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
	startErrorSidecars(t, []uint{10023}, stubPort, ErrorDuringDKG{scheme: crypto.NewBLSSuite(), url: "http://localhost:10023"})

	operators := fmap(append(ports, 10023), func(o uint) string {
		return fmt.Sprintf("http://localhost:%d", o)
	})

	depositData := []byte("hello world")

	_, err := cli.Sign(operators, depositData, shared.QuietLogger{Quiet: false})
	require.Error(t, err)
}

func startStubSSVNode(t *testing.T, ssvPort uint) {
	go func() {
		stub.StartStub(ssvPort)
	}()
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
	return out
}

func startErrorSidecars(t *testing.T, ports []uint, ssvPort uint, errorCooordinator dkg.Protocol) []sidecar.Daemon {
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
	return out
}

func createErrorDaemon(t *testing.T, port uint, ssvPort uint, errorCoordinator dkg.Protocol) sidecar.Daemon {
	keyPath := path.Join(t.TempDir(), strconv.Itoa(int(port)), "keypair.json")
	err := sidecar.GenerateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	url := fmt.Sprintf("http://localhost:%d", port)
	_, err = sidecar.SignKey(url, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	ssvURL := fmt.Sprintf("http://localhost:%d", ssvPort)
	d, err := sidecar.NewDaemonWithDKG(port, url, ssvURL, keyPath, errorCoordinator)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func createDaemon(t *testing.T, port uint, ssvPort uint) sidecar.Daemon {
	keyPath := path.Join(t.TempDir(), strconv.Itoa(int(port)), "keypair.json")
	err := sidecar.GenerateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	url := fmt.Sprintf("http://localhost:%d", port)
	_, err = sidecar.SignKey(url, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	ssvURL := fmt.Sprintf("http://localhost:%d", ssvPort)
	d, err := sidecar.NewDaemon(port, url, ssvURL, keyPath)
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
	c := api.NewSidecarClient(fmt.Sprintf("http://localhost:%d", port))
	var err error
	for i := 0; i < 5; i++ {
		if err = c.Health(); err == nil {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return err
}
