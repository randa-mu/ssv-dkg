package sidecar

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignKey(t *testing.T) {
	stateDir := t.TempDir()
	require.NoError(t, GenerateKey(stateDir))

	type args struct {
		url        string
		stateDir   string
		operatorID uint32
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "everything correct succeeds",
			args: args{
				url:        "https://example.com",
				stateDir:   stateDir,
				operatorID: 1,
			},
			wantErr: false,
		},
		{
			name: "empty URL fails",
			args: args{
				url:        "",
				stateDir:   stateDir,
				operatorID: 1,
			},
			wantErr: true,
		},
		{
			name: "invalid dir fails",
			args: args{
				url:        "https://example.com",
				stateDir:   "some-fake-dir",
				operatorID: 1,
			},
			wantErr: true,
		},
		{
			name: "missing operatorID fails",
			args: args{
				url:      "https://example.com",
				stateDir: stateDir,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signedKey, err := SignKey(tt.args.url, tt.args.stateDir, tt.args.operatorID)
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
