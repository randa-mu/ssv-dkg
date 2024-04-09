package sidecar

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/go-chi/chi/v5"
	"github.com/randa-mu/ssv-dkg/shared/api"
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
	// fetch the public key of the SSV node
	validatorIdentity, err := d.ssvClient.Identity()
	if err != nil {
		slog.Error("error fetching SSV node public key", err)
		return api.SignResponse{}, err
	}

	// run the DKG protocol to retrieve a key share for signing
	result, err := d.dkg.RunDKG(request.Operators, request.SessionID, d.key)
	if err != nil {
		slog.Error("error running DKG", err)
		return api.SignResponse{}, err
	}

	// blow up if any nodes failed to qualify for the final group
	if len(result.NodePublicKeys) != len(request.Operators) {
		msg := "not all operators completed the DKG successfully"
		slog.Error(msg)
		return api.SignResponse{}, errors.New(msg)
	}

	// sign the deposit data using the key share
	partialSignature, err := d.thresholdScheme.SignWithPartial(result.KeyShare, request.Data)
	if err != nil {
		slog.Error("error signing deposit data", err)
		return api.SignResponse{}, err
	}

	// encrypt the key share for use by the SSV node later via smart contract
	encryptedShare, err := d.encryptionScheme.Encrypt(validatorIdentity.PublicKey, result.KeyShare)
	if err != nil {
		slog.Error("error encrypting key share", err)
		return api.SignResponse{}, err
	}

	// encrypt the validator nonce
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, request.ValidatorNonce)
	encryptedNonce, err := d.encryptionScheme.Encrypt(validatorIdentity.PublicKey, buf)
	if err != nil {
		slog.Error("error encrypting nonce", err)
		return api.SignResponse{}, err
	}

	slog.Info(fmt.Sprintf("DKG with sessionID %s completed successfully", hex.EncodeToString(request.SessionID)))

	return api.SignResponse{
		PublicPolynomial:               result.GroupPublicPoly,
		NodePK:                         result.PublicKeyShare,
		DepositDataPartialSignature:    partialSignature,
		EncryptedShare:                 encryptedShare,
		DepositValidatorNonceSignature: encryptedNonce,
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
