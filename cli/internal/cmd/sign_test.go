package cmd

import (
	"encoding/json"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/randa-mu/ssv-dkg/shared/api"
)

func TestSignCommand(t *testing.T) {
	tmp := t.TempDir()
	filepath := path.Join(tmp, "testfile")
	createdUnsignedDepositData(t, filepath)

	tests := []struct {
		name        string
		args        []string
		stdin       *strings.Reader
		shouldError bool
	}{
		{
			name:        "expected flags succeeds",
			shouldError: false,
			args: []string{
				"ssv-dkg",
				"sign",
				"--deposit-file", filepath,
				"--output", filepath,
				"--validator-nonce", "1",
				"--owner-address", "0xdeadbeef",
				"--operator", "http://127.0.0.1:8081",
				"--operator", "http://127.0.0.1:8082",
				"--operator", "http://127.0.0.1:8083",
			},
		},
		{
			name:        "operators from stdin works",
			shouldError: false,
			args: []string{
				"ssv-dkg",
				"sign",
				"--deposit-file", filepath,
				"--output", filepath,
				"--validator-nonce", "1",
				"--owner-address", "0xdeadbeef",
				"--operator", "http://127.0.0.1:8081",
				"--operator", "http://127.0.0.1:8082",
				"--operator", "http://127.0.0.1:8083",
			},
			stdin: strings.NewReader("http://127.0.0.1:8081 http://127.0.0.1:8082 http://127.0.0.1:8083"),
		},
		{
			name:        "no input returns error",
			shouldError: true,
			args: []string{
				"ssv-dkg",
				"sign",
				"--output", filepath,
				"--validator-nonce", "1",
				"--owner-address", "0xdeadbeef",
				"--operator", "http://127.0.0.1:8081",
				"--operator", "http://127.0.0.1:8082",
				"--operator", "http://127.0.0.1:8083",
			},
		},
		{
			name:        "no operators returns error",
			shouldError: true,
			args: []string{
				"ssv-dkg",
				"sign",
				"--owner-address", "0xdeadbeef",
				"--validator-nonce", "1",
				"--deposit-file", filepath,
				"--output", filepath,
			},
		},
		{
			name:        "missing validator nonce returns error",
			shouldError: true,
			args: []string{
				"ssv-dkg",
				"sign",
				"--deposit-file", filepath,
				"--output", filepath,
				"--operator", "http://127.0.0.1:8081",
				"--operator", "http://127.0.0.1:8082",
				"--operator", "http://127.0.0.1:8083",
			},
		},
		{
			name:        "negative validator nonce returns error",
			shouldError: true,
			args: []string{
				"ssv-dkg",
				"sign",
				"--deposit-file", filepath,
				"--output", filepath,
				"--validator-nonce", "-1",
				"--owner-address", "0xdeadbeef",
				"--operator", "http://127.0.0.1:8081",
				"--operator", "http://127.0.0.1:8082",
				"--operator", "http://127.0.0.1:8083",
			},
		},
		{
			name:        "no owner address returns error",
			shouldError: true,
			args: []string{
				"ssv-dkg",
				"sign",
				"--deposit-file", filepath,
				"--output", filepath,
				"--validator-nonce", "1",
				"--operator", "http://127.0.0.1:8081",
				"--operator", "http://127.0.0.1:8082",
				"--operator", "http://127.0.0.1:8083",
			},
		},
		{
			name:        "non-hex validator address returns error",
			shouldError: true,
			args: []string{
				"ssv-dkg",
				"sign",
				"--deposit-file", filepath,
				"--output", filepath,
				"--validator-nonce", "1",
				"--owner-address", "0xzzzzzzz",
				"--operator", "http://127.0.0.1:8081",
				"--operator", "http://127.0.0.1:8082",
				"--operator", "http://127.0.0.1:8083",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.stdin == nil {
				test.stdin = strings.NewReader("")
			}
			signCmd.SetIn(test.stdin)
			signCmd.SetArgs(test.args)
			err := signCmd.ParseFlags(test.args)
			require.NoError(t, err)
			_, err = parseArgs(signCmd)

			t.Cleanup(func() {
				operatorFlag = nil
				inputPathFlag = ""
				shortFlag = false
				stateDirectoryFlag = ""
				ethAddressFlag = ""
				validatorNonceFlag = -1
			})
			if test.shouldError && err == nil {
				t.Fatalf("expected err but got nil")
			} else if !test.shouldError && err != nil {
				t.Fatalf("expected no err but got: %v", err)
			}
		})
	}
}

func createdUnsignedDepositData(t *testing.T, filepath string) {
	data := []api.UnsignedDepositData{

		{
			WithdrawalCredentials: []byte("hello worldhello worldhello worl"), // must be 32 bytes
			Amount:                1,
			ForkVersion:           "somefork",
			NetworkName:           "somenetwork",
			DepositCLIVersion:     "somecli",
		},
	}

	bytes, err := json.Marshal(data)
	require.NoError(t, err)
	file, err := os.Create(filepath)
	require.NoError(t, err)
	_, err = file.Write(bytes)
	require.NoError(t, err)
	err = file.Close()
	require.NoError(t, err)
}
