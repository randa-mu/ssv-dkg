package api

import (
	"errors"
	"net/http"
	"testing"

)

var (
	baseUrl = "https://example.org"
	client  = NewSidecarClient(baseUrl)
)

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
	signRequest := SignRequest{Data: []byte("deadbeef")}
	_, err := client.Sign(signRequest)
	require.Error(t, err)
}

func TestSidecarInvalidJsonDoesntPanic(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", "https://example.org/sign", httpmock.NewStringResponder(http.StatusOK, "{ invalid Json }"))
	signRequest := SignRequest{Data: []byte("deadbeef")}
	_, err := client.Sign(signRequest)
	require.Error(t, err)
}
