package internal

import (
	"encoding/hex"
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
	require.NotEmpty(t, signingOutput.GroupPublicKey)
	require.NotEmpty(t, signingOutput.OperatorShares)

	signingOutput, err = cli.Reshare(operators, signingOutput, log)
	require.NoError(t, err)
	require.NotEmpty(t, signingOutput)
	require.NotEmpty(t, signingOutput.DepositDataSignature)
	require.NotEmpty(t, signingOutput.GroupPublicKey)
	require.NotEmpty(t, signingOutput.OperatorShares)

	// reshare a second time with the same group just to confirm the polynomial commitments have been saved as expected
	signingOutput, err = cli.Reshare(operators, signingOutput, log)
	require.NoError(t, err)
	require.NotEmpty(t, signingOutput)
	require.NotEmpty(t, signingOutput.DepositDataSignature)
	require.NotEmpty(t, signingOutput.GroupPublicKey)
	require.NotEmpty(t, signingOutput.OperatorShares)

	// reshare a third time with a slightly different group
	startSidecars(t, []uint{10005})
	operators = append(operators[0:3], "http://127.0.0.1:10005")
	signingOutput, err = cli.Reshare(operators, signingOutput, log)
	require.NoError(t, err)
	require.NotEmpty(t, signingOutput)
	require.NotEmpty(t, signingOutput.DepositDataSignature)
	require.NotEmpty(t, signingOutput.GroupPublicKey)
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
	require.NotEmpty(t, signingOutput.GroupPublicKey)
	require.NotEmpty(t, signingOutput.OperatorShares)

	// reshare a third time with a slightly different group
	startSidecars(t, []uint{10006})
	operators = append(operators[0:3], "http://127.0.0.1:10006")
	signingOutput, err = cli.Reshare(operators, signingOutput, log)
	require.NoError(t, err)
	require.NotEmpty(t, signingOutput)
	require.NotEmpty(t, signingOutput.DepositDataSignature)
	require.NotEmpty(t, signingOutput.GroupPublicKey)
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
			t.Fatalf("error starting sidecar: %v", err)
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
			t.Fatalf("error starting sidecar: %v", err)
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

func generateRSAKey(path string) error {
	// this json is a sample created from an SSV node that's created an encrypted key
	j := "{\"checksum\":{\"function\":\"sha256\",\"message\":\"46542dce0fe705e4ee991028eeae8f660fb0f4f3f070d9877b3a8816708be2e8\",\"params\":{}},\"cipher\":{\"function\":\"aes-128-ctr\",\"message\":\"5a2f1a5073f43473365161ee59b3a5a3c1b2a72df350533d80dc4d7ac9e4e3a2e2571cf1d0db545162c923b34ea93eff64016c61d7829d0845b0e58baa67706677013c8091bf755f7a7b2fe4d54e89558164c46bc7f1986449f424e00e3df232d23618e0631d6a016d94a3ddff94386db32102ee401e9449b1da223d7ffd13e23499f9956edf9b085283bb1490a4c341b0c7c909762c822a45fa31744c1c3fe80279c0efe037b6e979bddc5e48eae6934b670de970eaefa5d125671682e06773384cbad0c165b82d78e62512823c31a925ac855447805e31f73fd749ad18c5e1234541f8efe9ab850f2ac3e72ae5270b18b4f0c21583705d67e626598718f84d2c7abd0c1ea82686737369b08bf6553315beb79e847afc9224276a298dc76e7ba71075e33e21347adb4cd3669fb24e85f953928060cca692f6a8a205b75475fa83083cbe9cd975ca7f3bc0f23429c814ea02c2dfd2581d660515abc86344f14f7e88d22eda599fc5cd5ded55e3df920b5f5f0a9dfd127ff2716c70ed8d276ce961185c21034fc79c18ce92cad939856f4ee16aa5a6baea77c1d66c07539a40f67e23c76c25f4c98c89e087200541dd321fabf9104200f1ce56c2914bbcf258a376d833802e2548a524243eaaa3a3421b00d0999cf72cb486a453bbc57f8ccba885359064e404d033d6228265ab6b98112f16c0a1f050cc8fa3ca175ae03e330cac75c745e58fde06efb2f5259b6c84d13d6e4c0a27b2be62e003f56cfa76cfb64b104b6bedf13c86d43a3462176ef832b945723ba051e2ad06e09a7d84adf0c18f62b63a67d93c5f7a63ddc3ff72bbbd41fb64cfc24902a6840d910987c6d5f8cc8d44baaed32641dd38873ffddaa4cb9b7b5ebe9047e3295a5fab68a88edc6c3b54d9d3de44133d511008f612ea0d15d86b671ec89a2935977e543350550b67e4554e2d2a406005872bbfed1d5e4252fb35f7c9ab6d1b400abdca69f3f96836fae7c9558c276bc524f8a802531b6194d2bd187f618595f817013304cc1d12e5e42c2871732443d9798640c52be86c48270d47129e6c8706795290cb4f8b6f5d12f0f8e4dcfb5cf90aab61ccc249fd1a2fc97bf79d0248aef7a69e47c83e51bafb3ee9ebf6e41a1ae1dcab40dfd067ba70262a216f339e5af7041df16d1882dee68123454ac41354dd49a8195873f7184124d239a6e1a54d79e436716f8dacaf0f04877fa93448d38b55e885dddd9fe686ccec9237c06eda8a2e8ecf20c5fd9eb8bf09d6d020479c50ad70a099baf24ae2960c83b6e9e75929b7c6241a0429719a54249909f0647a5bc5ab6acef642cccd15be77ddfceff327588395cf4b6abdafcf53379debd876c6101127cb44154cd4b5e882bbf446f202a4ebb383d567ce0c4d7752c206546629d6a269874f00226cdf9a67c896f0f6d39e242686cf17d9d2cb71d13c4becc06b39cd65972a00fff1ae561e9a4afcc75c14464fcf55cf8fff7b783b8077366b20656b8bf493feded958beb2b81e94c6180c9df73656a9f6d4ce28770f8bbf275a3bc965287d38a7efd215da140b1af05f03e3e7d31500cc38b767516827c25b7de56c7d001e3702747abb9158e19f3dd6c9f71c650cdee829bb41ee63e29598e3a959aef452cbc1b769e6ca96fa76b116fc9a93232c653bc96d2f100c5423c794e6f6282b58de3ae1418e12cb6fa0c719b3e77d7de07ac0ac0c41163d670672a125c1e99d2817c18272d2b9b6e6565df3afd1f1efa3fde0407809870d564db0082c88e434fcba8c3c318d5cfe5c88f4063cf1598a824d28798cc90dbae4b24abae633ad7774f0eed042d0f5886699840cfe82bee0478a997fabc900293345cd580e4e97a0df0934be23224608de335dc7b29faa1e9f5b8de8cbdc77b44615c1313e27cba3364490fe7b0c7dbed993211471a64871c2f3c793d9684b8f4d621db4da25ab9e92d9c2ededa5e6df162d59bebe3faf72361df8ad42454fb56de17d306fb7ae33169e373505606015585a524f627e2539a82233e338a223812e6fa8611ffbd206af28966c913567ad8a4e81fa072a4dd6c9022146aca829275f252d34ca42b4d77477e7e11fb36088752fd6df662a50914dd5a10cf9424df5c1e198a642b6a238e6a037d8fa107019d86488d680f392dc7f4d8609ad80df0b80ddb56014047b04c24de6ef167f0b4010eca9efc8b2c288d0c3194ef2d2535d6b0e7117c59f52e7c38fbe2ac42f2e2a7769c0f64b07278873d4b2199508835bd965199d8e820f3fd6aa83e39ce1bb1c1c4924f29e591c3f07baff238a481f4c8b714bc952e54425d80d2b137626510e6196c8bba52332d9bc57d1494f1a57105e67608f0404c560f981\",\"params\":{\"iv\":\"2143cda25288d8225f4b21e3499542eb\"}},\"kdf\":{\"function\":\"pbkdf2\",\"message\":\"\",\"params\":{\"c\":262144,\"dklen\":32,\"prf\":\"hmac-sha256\",\"salt\":\"03491c71fe76a466417984ad440dcab381cd5f547f8648eea9b40714a93bde01\"}},\"pubKey\":\"LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBNG0xa2Y1NDBXZ0lkdVdzaFNCc2MKbzhnQUZUUmhQU0NvM2VuRHFEb1JaVnh1YTZWWGFOdmdkRkloVm42Mm43RkRlaHdrY2NDVHNyRUYzVWJTRTVBMApDUStXT05xMTRCcEFPaUlpT0gydlV6YUNuaVZ0NTIxMDlkWmQwRWxXZjY2NVIvZHB3MFlrdUxpaUhWZnVYNHZ6ClVjclN1RlBqNXdIenY4aWs0R1FkUGJMenphU0REdXVZQnhmaGVGaTk3SDJTS0ZJdUxiVWNOb1B1L25udUtWN0QKQW5CTzlOOU4rQW9tNUYyRTBUVmpKa1RqZXJ6dmtTTGVXU0x1U2w5TGlRL28xUUlhOHBsVE1QTlFxOVRZVDJhMgo1aG5qbTF3QW9uOFRjWmFDSkNPSitlclpyS0p3Si9FVlRGNlpqamlXVVNtSDIyTjFGanpTaWs4Q3lSN1dFZEcwCldRSURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K\"}"

	return os.WriteFile(path, []byte(j), 0o755)
}
