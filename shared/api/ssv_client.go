package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type SsvClient struct {
	baseUrl string
}

func DefaultSsvClient() SsvClient {
	return SsvClient{
		baseUrl: "https://api.ssv.network/api/v4",
	}
}

type SsvApiResponse struct {
	PublicKey []byte `json:"public_key"`
}

func (s SsvClient) FetchPublicKeyFromSsv(operatorID uint32) (SsvApiResponse, error) {
	res, err := http.Get(fmt.Sprintf("%s/mainnet/operators/%d", s.baseUrl, operatorID))
	if err != nil {
		return SsvApiResponse{}, err
	}

	if res.StatusCode != http.StatusOK {
		return SsvApiResponse{}, fmt.Errorf("SSV API returned status code %d", res.StatusCode)
	}

	responseBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return SsvApiResponse{}, fmt.Errorf("error reading Response body: %w", err)
	}

	var apiResponse SsvApiResponse
	err = json.Unmarshal(responseBytes, &apiResponse)
	if err != nil {
		return SsvApiResponse{}, fmt.Errorf("error marshalling response body: %w", err)
	}
	return apiResponse, nil
}
