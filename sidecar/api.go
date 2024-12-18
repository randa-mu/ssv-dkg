package sidecar

import (
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"

	"github.com/go-chi/chi/v5"
	"golang.org/x/exp/slog"

	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	dkg "github.com/randa-mu/ssv-dkg/sidecar/dkg"
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
		slog.Error("error fetching SSV node public key", "err", err)
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
	depositDataMessage, err := crypto.DepositDataMessage(request.Data.ExtractRequired(), result.GroupPublicPoly)
	if err != nil {
		return api.SignResponse{}, err
	}
	partialSignature, err := d.thresholdScheme.SignWithPartial(result.KeyShare, depositDataMessage)
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

	// sign the validator nonce to prevent replays
	signedNonce, err := d.thresholdScheme.Sign(d.key, crypto.ValidatorNonceMessage(request.ValidatorNonce))
	if err != nil {
		slog.Error("error signing nonce", "sessionID", sessionID, "err", err)
		return api.SignResponse{}, err
	}

	response := api.SignResponse{
		PublicPolynomial:               result.GroupPublicPoly,
		NodePK:                         result.PublicKeyShare,
		DepositDataPartialSignature:    partialSignature,
		EncryptedShare:                 encryptedShare,
		DepositValidatorNonceSignature: signedNonce,
	}

	groupFile, err := dkg.NewGroupFile(sessionID, result.GroupPublicPoly, request.Operators, result.KeyShare, encryptedShare)
	if err != nil {
		slog.Error("error creating group file", "sessionID", sessionID, "err", err)
		return api.SignResponse{}, err
	}

	err = d.db.Save(groupFile)
	if err != nil {
		slog.Error("error storing DKG results", "sessionID", sessionID, "err", err)
		return api.SignResponse{}, err
	}

	slog.Info(fmt.Sprintf("DKG with sessionID %s completed successfully", sessionID))

	return response, nil
}

func (d Daemon) Reshare(request api.ReshareRequest) (api.ReshareResponse, error) {
	sessionIDHex := request.PreviousState.SessionID
	sessionID, err := hex.DecodeString(sessionIDHex)
	if err != nil {
		slog.Error("error decoding sessionID", "err", err)
		return api.ReshareResponse{}, fmt.Errorf("could not decode sessionID: %s", sessionID)
	}
	if request.PreviousState.SessionID == "" {
		slog.Error("received invalid sessionID for reshare")
		return api.ReshareResponse{}, errors.New("sessionID cannot be nil for a reshare")
	}

	// fetch the public key of the SSV node
	validatorIdentity, err := d.ssvClient.Identity()
	if err != nil {
		slog.Error("error fetching SSV node public key", "err", err)
		return api.ReshareResponse{}, err
	}

	dkgState, err := d.db.LoadSingle(sessionIDHex, request.PreviousEncryptedShareHash)
	if err != nil {
		slog.Error("error loading previous state from database", "err", err)
		return api.ReshareResponse{}, err
	}

	var previousState dkg.GroupFile
	if reflect.DeepEqual(dkg.GroupFile{}, dkgState) {
		slog.Debug("no previous state found for DKG")
		previousState = dkg.GroupFile{
			SessionID:                   request.PreviousState.SessionID,
			Nodes:                       request.PreviousState.Nodes,
			PublicPolynomialCommitments: request.PreviousState.PublicPolynomialCommitments,
			EncryptedKeyShareHash:       request.PreviousEncryptedShareHash,
			// our node wasn't in the previous group, so it doesn't have a key share
			KeyShare: nil,
		}
	} else {
		// although we store a bunch of state, in case of some failures it's better to trust the client on the commitments etc
		previousState = dkg.GroupFile{
			SessionID:                   request.PreviousState.SessionID,
			Nodes:                       request.PreviousState.Nodes,
			PublicPolynomialCommitments: request.PreviousState.PublicPolynomialCommitments,
			EncryptedKeyShareHash:       request.PreviousEncryptedShareHash,
			KeyShare:                    dkgState.KeyShare,
		}
	}

	// run the resharing protocol to receive a new partial key
	result, err := d.dkg.RunReshare(request.Operators, sessionID, d.key, previousState)
	if err != nil {
		slog.Error("error running resharing", "sessionID", request.PreviousState.SessionID, "err", err)
		return api.ReshareResponse{}, err
	}

	// blow up if any nodes failed to qualify for the final group
	if len(result.NodePublicKeys) != len(request.Operators) {
		msg := "not all operators completed the DKG successfully"
		slog.Error(msg, "sessionID", sessionIDHex)
		return api.ReshareResponse{}, errors.New(msg)
	}

	// encrypt the key share for use by the SSV node later via smart contract
	encryptedShare, err := d.encryptionScheme.Encrypt(validatorIdentity.PublicKey, result.KeyShare)
	if err != nil {
		slog.Error("error encrypting key share", "sessionID", sessionIDHex, "err", err)
		return api.ReshareResponse{}, err
	}

	// store the results of the resharing
	groupFile, err := dkg.NewGroupFile(sessionIDHex, result.GroupPublicPoly, request.Operators, result.KeyShare, encryptedShare)
	if err != nil {
		slog.Error("error creating group file", "sessionID", sessionID, "err", err)
		return api.ReshareResponse{}, err
	}

	err = d.db.Save(groupFile)
	if err != nil {
		slog.Error("error storing DKG results", "sessionID", sessionIDHex, "err", err)
		return api.ReshareResponse{}, err
	}

	slog.Info(fmt.Sprintf("Resharing with sessionID %s completed successfully", sessionIDHex))

	return api.ReshareResponse{
		EncryptedShare:   encryptedShare,
		PublicPolynomial: result.GroupPublicPoly,
		NodePK:           result.PublicKeyShare,
	}, nil
}

func (d Daemon) Identity(request api.SidecarIdentityRequest) (api.SidecarIdentityResponse, error) {
	identity, err := d.key.SelfSign(d.thresholdScheme, d.publicURL)
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
