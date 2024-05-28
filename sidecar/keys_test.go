package sidecar

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignKey(t *testing.T) {
	stateDir := t.TempDir()
	require.NoError(t, GenerateKey(stateDir))

	type args struct {
		url            string
		validatorNonce uint32
		stateDir       string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "everything correct succeeds",
			args: args{
				url:            "https://example.com",
				validatorNonce: 1,
				stateDir:       stateDir,
			},
			wantErr: false,
		},
		{
			name: "empty URL fails",
			args: args{
				url:            "",
				validatorNonce: 1,
				stateDir:       stateDir,
			},
			wantErr: true,
		},
		{
			name: "0 validatorNonce fails",
			args: args{
				url:            "https://example.com",
				validatorNonce: 0,
				stateDir:       stateDir,
			},
			wantErr: true,
		},
		{
			name: "invalid dir fails",
			args: args{
				url:            "https://example.com",
				validatorNonce: 1,
				stateDir:       "some-fake-dir",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signedKey, err := SignKey(tt.args.url, tt.args.validatorNonce, tt.args.stateDir)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, signedKey)
				require.NotEmpty(t, signedKey)
			}
		})
	}
}
