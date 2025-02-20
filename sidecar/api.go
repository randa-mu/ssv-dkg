package sidecar

import (
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"

	"github.com/go-chi/chi/v5"
	"github.com/randa-mu/ssv-dkg/shared"
	"golang.org/x/exp/slog"

	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"github.com/randa-mu/ssv-dkg/sidecar/dkg"
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
	groupPublicKey := crypto.ExtractGroupPublicKey(d.thresholdScheme, result.GroupPublicPoly)
	depositDataMessage, err := crypto.DepositMessageSigningRoot(request.DepositData.IntoMessage(shared.Clone(groupPublicKey)), request.DepositData.ForkVersion)
	if err != nil {
		return api.SignResponse{}, err
	}
	depositDataPartialSignature, err := d.thresholdScheme.SignWithPartial(result.KeyShare, depositDataMessage)
	if err != nil {
		slog.Error("error signing deposit data", "sessionID", sessionID, "err", err)
		return api.SignResponse{}, err
	}

	// we encrypt the secret key share for use by the SSV node later via smart contract.
	// The first 64 bits are the index used in the DKG which are not in the spec
	// for how SSV uses the keyshares, so we trim them off
	share := crypto.DistKeyWithoutIndex(result.KeyShare)
	// then for some reason it's encoded in hex and passed as a utf8 string
	encodedShare := []byte(hex.EncodeToString(share))

	encryptedShare, err := d.encryptionScheme.Encrypt(d.ssvKey, encodedShare)
	if err != nil {
		slog.Error("error encrypting key share", "sessionID", sessionID, "err", err)
		return api.SignResponse{}, err
	}

	// sign the validator nonce to prevent operators signing up the same validator twice
	validatorNonceMessage, err := crypto.ValidatorNonceMessage(request.OwnerConfig.Address, request.OwnerConfig.ValidatorNonce)
	if err != nil {
		return api.SignResponse{}, fmt.Errorf("error creating validator nonce message: %v", err)
	}

	signedNonce, err := d.thresholdScheme.SignWithPartial(result.KeyShare, validatorNonceMessage)
	if err != nil {
		slog.Error("error signing nonce", "sessionID", sessionID, "err", err)
		return api.SignResponse{}, err
	}

	response := api.SignResponse{
		PublicPolynomial:               result.GroupPublicPoly,
		DepositDataPartialSignature:    depositDataPartialSignature,
		EncryptedShare:                 encryptedShare,
		SharePublicKey:                 result.PublicKeyShare,
		ValidatorNoncePartialSignature: signedNonce,
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

	// we encrypt the secret key share for use by the SSV node later via smart contract.
	// The first 64 bits are the index used in the DKG which are not in the spec
	// for how SSV uses the keyshares, so we trim them off
	share := crypto.DistKeyWithoutIndex(result.KeyShare)
	// then for some reason it's encoded in hex and passed as a utf8 string
	encodedShare := []byte(hex.EncodeToString(share))
	encryptedShare, err := d.encryptionScheme.Encrypt(d.ssvKey, encodedShare)
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
		PublicKeyShare:   result.PublicKeyShare,
		PublicPolynomial: result.GroupPublicPoly,
	}, nil
}

func (d Daemon) Identity() (api.SidecarIdentityResponse, error) {
	identity, err := d.key.SelfSign(d.thresholdScheme, d.publicURL, d.operatorID)
	if err != nil {
		return api.SidecarIdentityResponse{}, err
	}

	return api.SidecarIdentityResponse{
		OperatorID: identity.OperatorID,
		PublicKey:  identity.Public,
		Address:    identity.Address,
		Signature:  identity.Signature,
	}, nil
}

func (d Daemon) BroadcastDKG(packet api.SidecarDKGPacket) error {
	return d.dkg.ProcessPacket(packet)
}
