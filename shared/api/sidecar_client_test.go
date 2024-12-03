package api

import (
	"errors"
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/require"
)

var baseUrl = "https://example.org"
var client = NewSidecarClient(baseUrl)
var depositData = UnsignedDepositData{
	WithdrawalCredentials: []byte("hello worldhello worldhello worl"), // must be 32 bytes
	DepositDataRoot:       []byte("cafebabe"),
	DepositMessageRoot:    []byte("b00b00b"),
	Amount:                1,
	ForkVersion:           "myfork123",
	NetworkName:           "holesky",
	DepositCLIVersion:     "1.2.3",
}

func TestSidecarHealthUp(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "https://example.org/health", httpmock.NewStringResponder(http.StatusOK, ""))
	err := client.Health()
	require.NoError(t, err)
	require.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestSidecarHealthDown(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "https://example.org/health", httpmock.NewStringResponder(http.StatusServiceUnavailable, ""))
	err := client.Health()
	require.Error(t, err)
	require.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestSidecarHealthErr(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	expectedErr := errors.New("downstream")
	httpmock.RegisterResponder("GET", "https://example.org/health", httpmock.NewErrorResponder(expectedErr))

	err := client.Health()
	require.ErrorIs(t, err, expectedErr)
	require.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestSidecarSignErrReturned(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	expectedErr := errors.New("downstream")
	httpmock.RegisterResponder("POST", "https://example.org/sign", httpmock.NewErrorResponder(expectedErr))
	signRequest := SignRequest{Data: depositData}
	_, err := client.Sign(signRequest)
	require.Error(t, err)
}

func TestSidecarInvalidJsonDoesntPanic(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", "https://example.org/sign", httpmock.NewStringResponder(http.StatusOK, "{ invalid Json }"))
	signRequest := SignRequest{Data: depositData}
	_, err := client.Sign(signRequest)
	require.Error(t, err)
}
