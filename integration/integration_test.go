package integration

import (
	"fmt"
	"github.com/randa-mu/ssv-dkg/cli"
	"github.com/randa-mu/ssv-dkg/shared"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/sidecar"
	"github.com/randa-mu/ssv-dkg/tools/stub"
	"github.com/stretchr/testify/require"
	"path"
	"strconv"
	"testing"
	"time"
)

func TestEndToEndFlow(t *testing.T) {
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

func startStubSSVNode(t *testing.T, ssvPort uint) {
	go func() {
		stub.StartStub(ssvPort)
	}()
	err := awaitHealthy(ssvPort)
	if err != nil {
		t.Errorf("error starting SSV stub: %w", err)
		t.FailNow()
	}
}

func startSidecars(t *testing.T, ports []uint, ssvPort uint) {
	for _, o := range ports {
		d, err := createDaemon(t, o, ssvPort)
		require.NoError(t, err)
		go func() {
			d.Start()
		}()
		err = awaitHealthy(o)
		if err != nil {
			t.Errorf("error starting stub: %w", err)
			t.FailNow()
		}
	}
}

func createDaemon(t *testing.T, port uint, ssvPort uint) (sidecar.Daemon, error) {
	keyPath := path.Join(t.TempDir(), strconv.Itoa(int(port)), "keypair.json")
	err := sidecar.GenerateKey(keyPath)
	if err != nil {
		return sidecar.Daemon{}, err
	}

	url := fmt.Sprintf("http://localhost:%d", port)
	_, err = sidecar.SignKey(url, keyPath)
	if err != nil {
		return sidecar.Daemon{}, err
	}
	ssvURL := fmt.Sprintf("http://localhost:%d", ssvPort)
	return sidecar.NewDaemon(port, url, ssvURL, keyPath)
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
