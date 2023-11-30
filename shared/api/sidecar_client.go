package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type SidecarClient struct {
	url string
}

func NewSidecarClient(url string) Sidecar {
	return SidecarClient{url: url}
}

func (s SidecarClient) Health() error {
	res, err := http.Get(fmt.Sprintf("%s%s", s.url, SidecarHealthPath))
	if err != nil {
		return err
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("sidecar health returned %d", res.StatusCode)
	}
	return nil
}

func (s SidecarClient) Sign(request SignRequest) (SignResponse, error) {
	j, err := json.Marshal(request)
	if err != nil {
		return SignResponse{}, err
	}
	response, err := http.Post(fmt.Sprintf("%s/sign", s.url), "application/json", bytes.NewBuffer(j))

	if err != nil {
		return SignResponse{}, fmt.Errorf("error signing with validator %s: %v", s.url, err)
	}

	if response.StatusCode != http.StatusOK {
		return SignResponse{}, fmt.Errorf("error signing with validator %s. Node return status code %d", s.url, response.StatusCode)
	}

	responseBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return SignResponse{}, fmt.Errorf("error reading response bytes: %v", err)
	}

	var signResponse SignResponse
	err = json.Unmarshal(responseBytes, &signResponse)
	return signResponse, err
}
