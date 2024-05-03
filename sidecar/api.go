package sidecar

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/go-chi/chi/v5"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/sidecar/dkg"
	"golang.org/x/exp/slog"
)

func createAPI(d Daemon) *chi.Mux {
	router := chi.NewMux()
	api.BindSidecarAPI(router, d)
	return router
}

func (d Daemon) Health() error {
	return nil
}

func (d Daemon) Sign(request api.SignRequest) (api.SignResponse, error) {
	sessionID := hex.EncodeToString(request.SessionID)

	// fetch the public key of the SSV node
	validatorIdentity, err := d.ssvClient.Identity()
	if err != nil {
		slog.Error("error fetching SSV node public key", err)
		return api.SignResponse{}, err
	}

	// run the DKG protocol to retrieve a key share for signing
	result, err := d.dkg.RunDKG(request.Operators, request.SessionID, d.key)
	if err != nil {
		slog.Error("error running DKG", "sessionID", sessionID, "err", err)
		return api.SignResponse{}, err
	}

	// blow up if any nodes failed to qualify for the final group
	if len(result.NodePublicKeys) != len(request.Operators) {
		msg := "not all operators completed the DKG successfully"
		slog.Error(msg, "sessionID", sessionID)
		return api.SignResponse{}, errors.New(msg)
	}

	// sign the deposit data using the key share
	partialSignature, err := d.thresholdScheme.SignWithPartial(result.KeyShare, request.Data)
	if err != nil {
		slog.Error("error signing deposit data", "sessionID", sessionID, "err", err)
		return api.SignResponse{}, err
	}

	// encrypt the key share for use by the SSV node later via smart contract
	encryptedShare, err := d.encryptionScheme.Encrypt(validatorIdentity.PublicKey, result.KeyShare)
	if err != nil {
		slog.Error("error encrypting key share", "sessionID", sessionID, "err", err)
		return api.SignResponse{}, err
	}

	// encrypt the validator nonce
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, request.ValidatorNonce)
	encryptedNonce, err := d.encryptionScheme.Encrypt(validatorIdentity.PublicKey, buf)
	if err != nil {
		slog.Error("error encrypting nonce", "sessionID", sessionID, "err", err)
		return api.SignResponse{}, err
	}

	response := api.SignResponse{
		PublicPolynomial:               result.GroupPublicPoly,
		NodePK:                         result.PublicKeyShare,
		DepositDataPartialSignature:    partialSignature,
		EncryptedShare:                 encryptedShare,
		DepositValidatorNonceSignature: encryptedNonce,
	}

	err = dkg.StoreDKG(d.stateDir, sessionID, result, request.Operators)
	if err != nil {
		slog.Error("error storing DKG results", "sessionID", sessionID, "err", err)
		return api.SignResponse{}, err
	}

	slog.Info(fmt.Sprintf("DKG with sessionID %s completed successfully", sessionID))

	return response, nil
}

func (d Daemon) Reshare(request api.ReshareRequest) (api.ReshareResponse, error) {
	sessionID := hex.EncodeToString(request.SessionID)

	// fetch the public key of the SSV node
	validatorIdentity, err := d.ssvClient.Identity()
	if err != nil {
		slog.Error("error fetching SSV node public key", err)
		return api.ReshareResponse{}, err
	}

	dkgState, err := dkg.LoadDKG(d.stateDir, sessionID)
	if err != nil {
		return api.ReshareResponse{}, err
	}

	// run the resharing protocol to receive a new partial key
	result, err := d.dkg.RunReshare(request.Operators, request.SessionID, d.key, dkgState)
	if err != nil {
		slog.Error("error running resharing", "sessionID", sessionID, "err", err)
		return api.ReshareResponse{}, err
	}

	// blow up if any nodes failed to qualify for the final group
	if len(result.NodePublicKeys) != len(request.Operators) {
		msg := "not all operators completed the DKG successfully"
		slog.Error(msg, "sessionID", sessionID)
		return api.ReshareResponse{}, errors.New(msg)
	}

	// encrypt the key share for use by the SSV node later via smart contract
	encryptedShare, err := d.encryptionScheme.Encrypt(validatorIdentity.PublicKey, result.KeyShare)
	if err != nil {
		slog.Error("error encrypting key share", "sessionID", sessionID, "err", err)
		return api.ReshareResponse{}, err
	}

	// store the results of the resharing
	err = dkg.StoreDKG(d.stateDir, sessionID, result, request.Operators)
	if err != nil {
		slog.Error("error storing DKG results", "sessionID", sessionID, "err", err)
		return api.ReshareResponse{}, err
	}

	slog.Info(fmt.Sprintf("Resharing with sessionID %s completed successfully", sessionID))

	return api.ReshareResponse{
		EncryptedShare:   encryptedShare,
		PublicPolynomial: result.GroupPublicPoly,
		NodePK:           result.PublicKeyShare,
	}, nil
}

func (d Daemon) Identity(request api.SidecarIdentityRequest) (api.SidecarIdentityResponse, error) {
	identity, err := d.key.SelfSign(d.thresholdScheme, d.publicURL, request.ValidatorNonce)
	if err != nil {
		return api.SidecarIdentityResponse{}, err
	}

	return api.SidecarIdentityResponse{
		PublicKey: identity.Public,
		Address:   identity.Address,
		Signature: identity.Signature,
	}, nil
}

func (d Daemon) BroadcastDKG(packet api.SidecarDKGPacket) error {
	return d.dkg.ProcessPacket(packet)
}
