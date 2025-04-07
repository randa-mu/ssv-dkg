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

func MainnetSsvClient() SsvClient {
	return SsvClient{
		baseUrl: "https://api.ssv.network/api/v4/mainnet",
	}
}

func HoleskySsvClient() SsvClient {
	return SsvClient{
		baseUrl: "https://api.ssv.network/api/v4/holesky",
	}
}

func HoodiSsvClient() SsvClient {
	return SsvClient{
		baseUrl: "https://api.ssv.network/api/v4/hoodi",
	}
}

type SsvApiResponse struct {
	PublicKey []byte `json:"public_key"`
}

func (s SsvClient) FetchPublicKeyFromSsv(operatorID uint32) (SsvApiResponse, error) {
	res, err := http.Get(fmt.Sprintf("%s/operators/%d", s.baseUrl, operatorID))
	if err != nil {
		return SsvApiResponse{}, err
	}

	if res.StatusCode != http.StatusOK {
		return SsvApiResponse{}, fmt.Errorf("SSV API returned status code %d", res.StatusCode)
	}

	responseBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return SsvApiResponse{}, fmt.Errorf("error reading response body: %w", err)
	}

	var apiResponse SsvApiResponse
	err = json.Unmarshal(responseBytes, &apiResponse)
	if err != nil {
		return SsvApiResponse{}, fmt.Errorf("error marshalling response body: %w", err)
	}
	return apiResponse, nil
}
