package cmd

import (
	"os"
	"path"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignCommand(t *testing.T) {
	tmp := t.TempDir()
	filepath := path.Join(tmp, "testfile")
	createJunkFile(t, filepath)

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
				"--input", filepath,
				"--output", filepath,
				"--operator", "1,http://127.0.0.1:8081",
				"--operator", "2,http://127.0.0.1:8082",
				"--operator", "3,http://127.0.0.1:8083",
			},
		},
		{
			name:        "operators from stdin works",
			shouldError: false,
			args: []string{
				"ssv-dkg",
				"sign",
				"--input", filepath,
				"--output", filepath,
				"--operator", "1,http://127.0.0.1:8081",
				"--operator", "2,http://127.0.0.1:8082",
				"--operator", "3,http://127.0.0.1:8083",
			},
			stdin: strings.NewReader("1,http://127.0.0.1:8081 2,http://127.0.0.1:8082 3,http://127.0.0.1:8083"),
		},
		{
			name:        "no input returns error",
			shouldError: true,
			args: []string{
				"ssv-dkg",
				"sign",
				"--output", filepath,
				"--operator", "1,http://127.0.0.1:8081",
				"--operator", "2,http://127.0.0.1:8082",
				"--operator", "3,http://127.0.0.1:8083",
			},
		},
		{
			name:        "no operators returns error",
			shouldError: true,
			args: []string{
				"ssv-dkg",
				"sign",
				"--input", filepath,
				"--output", filepath,
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
			_, _, err = verifyAndGetArgs(signCmd)

			t.Cleanup(func() {
				operatorFlag = nil
				inputPathFlag = ""
				shortFlag = false
				stateDirectory = ""
			})
			if test.shouldError && err == nil {
				t.Fatalf("expected err but got nil")
			} else if !test.shouldError && err != nil {
				t.Fatalf("expected no err but got: %v", err)
			}
		})
	}
}

func createJunkFile(t *testing.T, filepath string) {
	file, err := os.Create(filepath)
	require.NoError(t, err)
	_, err = file.Write([]byte("hello"))
	require.NoError(t, err)
	err = file.Close()
	require.NoError(t, err)
}
