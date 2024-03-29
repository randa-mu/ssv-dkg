package sidecar

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignKey(t *testing.T) {
	keyPath := path.Join(t.TempDir(), "key.json")
	require.NoError(t, GenerateKey(keyPath))

	type args struct {
		url            string
		validatorNonce uint32
		keyPath        string
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
				keyPath:        keyPath,
			},
			wantErr: false,
		},
		{
			name: "empty URL fails",
			args: args{
				url:            "",
				validatorNonce: 1,
				keyPath:        keyPath,
			},
			wantErr: true,
		},
		{
			name: "0 validatorNonce fails",
			args: args{
				url:            "https://example.com",
				validatorNonce: 0,
				keyPath:        keyPath,
			},
			wantErr: true,
		},
		{
			name: "invalid dir fails",
			args: args{
				url:            "https://example.com",
				validatorNonce: 1,
				keyPath:        "some-fake-dir",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signedKey, err := SignKey(tt.args.url, tt.args.validatorNonce, tt.args.keyPath)
			if tt.wantErr {
				if err == nil {
					t.Errorf("SignKey() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				return
			}
			require.NotNil(t, signedKey)
			require.NotEmpty(t, signedKey)
		})
	}
}
