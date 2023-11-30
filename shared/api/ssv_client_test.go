package api

import (
	"errors"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

var ssvBaseUrl = "https://example.org"
var ssvClient = NewSsvClient(ssvBaseUrl)

func TestHealthUp(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "https://example.org/health", httpmock.NewStringResponder(http.StatusOK, ""))
	err := ssvClient.Health()
	require.NoError(t, err)
	require.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestHealthDown(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "https://example.org/health", httpmock.NewStringResponder(http.StatusServiceUnavailable, ""))
	err := ssvClient.Health()
	require.Error(t, err)
	require.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestHealthErr(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	expectedErr := errors.New("downstream")
	httpmock.RegisterResponder("GET", "https://example.org/health", httpmock.NewErrorResponder(expectedErr))

	err := ssvClient.Health()
	require.ErrorIs(t, err, expectedErr)
	require.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestIdentityErr(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	expectedErr := errors.New("downstream")
	httpmock.RegisterResponder("GET", "https://example.org/identity", httpmock.NewErrorResponder(expectedErr))

	_, err := ssvClient.Identity()
	require.ErrorIs(t, err, expectedErr)
	require.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestIdentityNon200(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "https://example.org/identity", httpmock.NewStringResponder(http.StatusServiceUnavailable, ""))

	_, err := ssvClient.Identity()
	require.Error(t, err)
	require.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestIdentityParsesValidJson(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	payload := `
{
  "publicKey": "MIICCgKCAgEA0RseLQ86JGMp4vLFiH30cYI3tHzHTxn1TkbSTOXNZcUDr6pSVchkpTw5vqc7F5+ZHwbeOOe0owFevWTGopID8FWG+8wobW3T8aZUWlnVVmjjkNkX1jXRbWbH5y3TJDdyrnjfYLr6vhfnq5SMj7luGdjkSuLRBj9IPPtupBGPldnWVNr7SzJXxKc9f5aZkcd/7+5NQ1A35d5i/xwqHPEarMoH1rYmTGSWb725Q5M08LY3PfrJQCNkn9dg4ze0aFWavupFEWJFG5Or4RhW39LYQA327u2wWSZd04pzT25HqROIAKR6/i2IeLsHITxq/X6wLkdBpfPuEQmdtYPR5QETanrlSo6qY+hpJWsezBUI6Pv0uzbM5r9Q84+c8XLMrEICPmEWQ9wtxsOeYeWRvUIO0GJtZUtO+6cE0dVwtzfAV0gYpxNjeeuMEQ4iUO2AbTaPlq0iieV8EleMyD8nX1cGae4qoCJMdubk+qF5fp+TDDGnjpb13+TKjiABtBJ+wFw8d/gWJLbeL62DboGCFfjfuyOC1d+qZ29N0Te+gdhDA0PWhjOshXGTPWm4Ju3iLB4MTURHYDVBMZ4zusYbPgQTCPx0Yq3Mn4frDjkf84wbgvavKtvDBzH5tHMqykPQIJMWuY8tkY2B5P/O9ZCqI+ejFdvSrayn43nHbh1KMcN1C0sCAwEAAQ==",
  "nonce": 1
}
`
	httpmock.RegisterResponder("GET", "https://example.org/identity", httpmock.NewStringResponder(http.StatusOK, payload))
	identity, err := ssvClient.Identity()
	require.NoError(t, err)
	require.Equal(t, identity.Nonce, uint64(1))
	require.NotEmpty(t, identity.PublicKey)
	require.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestIdentityInvalidJsonDoesnPanic(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	invalidPayload := `
{
  "publicKey": "MIICCgKCAgEA0RseLQ86JGMp4vLFiH30cYI3tHzHTxn1TkbSTOXNZcUDr6pSVchkpTw5vqc7F5+ZHwbeOOe0owFevWTGopID8FWG+8wobW3T8aZUWlnVVmjjkNkX1jXRbWbH5y3TJDdyrnjfYLr6vhfnq5SMj7luGdjkSuLRBj9IPPtupBGPldnWVNr7SzJXxKc9f5aZkcd/7+5NQ1A35d5i/xwqHPEarMoH1rYmTGSWb725Q5M08LY3PfrJQCNkn9dg4ze0aFWavupFEWJFG5Or4RhW39LYQA327u2wWSZd04pzT25HqROIAKR6/i2IeLsHITxq/X6wLkdBpfPuEQmdtYPR5QETanrlSo6qY+hpJWsezBUI6Pv0uzbM5r9Q84+c8XLMrEICPmEWQ9wtxsOeYeWRvUIO0GJtZUtO+6cE0dVwtzfAV0gYpxNjeeuMEQ4iUO2AbTaPlq0iieV8EleMyD8nX1cGae4qoCJMdubk+qF5fp+TDDGnjpb13+TKjiABtBJ+wFw8d/gWJLbeL62DboGCFfjfuyOC1d+qZ29N0Te+gdhDA0PWhjOshXGTPWm4Ju3iLB4MTURHYDVBMZ4zusYbPgQTCPx0Yq3Mn4frDjkf84wbgvavKtvDBzH5tHMqykPQIJMWuY8tkY2B5P/O9ZCqI+ejFdvSrayn43nHbh1KMcN1C0sCAwEAAQ==",
  nonce": 1
}
`
	httpmock.RegisterResponder("GET", "https://example.org/identity", httpmock.NewStringResponder(http.StatusOK, invalidPayload))
	_, err := ssvClient.Identity()
	require.Error(t, err)
	require.Equal(t, 1, httpmock.GetTotalCallCount())
}
