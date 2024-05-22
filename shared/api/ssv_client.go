package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type SsvClient struct {
	url string
}

func NewSsvClient(url string) SsvClient {
	return SsvClient{url: url}
}

func (s SsvClient) Health() error {
	res, err := http.Get(fmt.Sprintf("%s%s", s.url, SsvHealthPath))
	if err != nil {
		return fmt.Errorf("there was an error connecting to the SSV node: %v", err)
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("SSV health returned %d", res.StatusCode)
	}
	return nil
}

func (s SsvClient) Identity() (SsvIdentityResponse, error) {
	res, err := http.Get(fmt.Sprintf("%s%s", s.url, SsvIdentityPath))
	if err != nil {
		return SsvIdentityResponse{}, err
	}

	if res.StatusCode != 200 {
		return SsvIdentityResponse{}, fmt.Errorf("error fetching identity; status code %d", res.StatusCode)
	}

	bytes, err := io.ReadAll(res.Body)
	if err != nil {
		return SsvIdentityResponse{}, err
	}

	var pkResponse SsvIdentityResponse
	err = json.Unmarshal(bytes, &pkResponse)
	return pkResponse, err
}
