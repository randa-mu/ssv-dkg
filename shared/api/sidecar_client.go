package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/exp/slog"
)

type SidecarClient struct {
	url string
}

func NewSidecarClient(url string) Sidecar {
	return SidecarClient{url: url}
}

func (s SidecarClient) Health() error {
	url := fmt.Sprintf("%s%s", s.url, SidecarHealthPath)
	slog.Info("Sidecar running health check against", "url", url)
	res, err := http.Get(url)
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
	response, err := http.Post(fmt.Sprintf("%s%s", s.url, SidecarSignPath), "application/json", bytes.NewBuffer(j))
	if err != nil {
		return SignResponse{}, fmt.Errorf("error signing with validator %s: %w", s.url, err)
	}

	if response.StatusCode != http.StatusOK {
		return SignResponse{}, fmt.Errorf("error signing with validator %s. Node returned status code %d", s.url, response.StatusCode)
	}

	responseBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return SignResponse{}, fmt.Errorf("error reading Response bytes: %w", err)
	}

	var signResponse SignResponse
	err = json.Unmarshal(responseBytes, &signResponse)
	return signResponse, err
}

func (s SidecarClient) Reshare(request ReshareRequest) (ReshareResponse, error) {
	j, err := json.Marshal(request)
	if err != nil {
		return ReshareResponse{}, err
	}
	response, err := http.Post(fmt.Sprintf("%s%s", s.url, SidecarResharePath), "application/json", bytes.NewBuffer(j))
	if err != nil {
		return ReshareResponse{}, fmt.Errorf("error resharing with validator %s: %w", s.url, err)
	}

	if response.StatusCode != http.StatusOK {
		return ReshareResponse{}, fmt.Errorf("error resharing with validator %s. Node returned status code %d", s.url, response.StatusCode)
	}

	responseBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return ReshareResponse{}, fmt.Errorf("error reading response bytes: %w", err)
	}

	var reshareResponse ReshareResponse
	err = json.Unmarshal(responseBytes, &reshareResponse)
	return reshareResponse, err
}

func (s SidecarClient) Identity() (SidecarIdentityResponse, error) {
	res, err := http.Get(fmt.Sprintf("%s%s", s.url, SidecarIdentityPath))
	if err != nil {
		return SidecarIdentityResponse{}, fmt.Errorf("error making HTTP request: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return SidecarIdentityResponse{}, fmt.Errorf("error retrieving Identity for %s. Node returned status code %d", s.url, res.StatusCode)
	}

	responseBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return SidecarIdentityResponse{}, fmt.Errorf("error reading response body: %w", err)
	}

	var identity SidecarIdentityResponse
	err = json.Unmarshal(responseBytes, &identity)
	if err != nil {
		return SidecarIdentityResponse{}, fmt.Errorf("error marshalling response body: %w", err)
	}
	return identity, nil
}

func (s SidecarClient) BroadcastDKG(packet SidecarDKGPacket) error {
	requestBytes, err := json.Marshal(packet)
	if err != nil {
		return fmt.Errorf("error marshalling json: %w", err)
	}

	res, err := http.Post(fmt.Sprintf("%s%s", s.url, SidecarDKGPath), "application/json", bytes.NewBuffer(requestBytes))
	if err != nil {
		return fmt.Errorf("error making HTTP request: %w", err)
	}
	if res.StatusCode != http.StatusNoContent {
		return fmt.Errorf("error broadcasting DKG to %s. Node returned status code %d", s.url, res.StatusCode)
	}
	return nil
}
