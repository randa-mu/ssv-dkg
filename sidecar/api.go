package sidecar

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/drand/kyber/share"
	"github.com/go-chi/chi/v5"
	"github.com/randa-mu/ssv-dkg/shared/api"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"github.com/rs/zerolog/log"
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
		log.Error().Err(err).Msg("error fetching SSV node public key")
		return api.SignResponse{}, err
	}

	// run the DKG protocol to retrieve a key share for signing
	result, err := d.dkg.RunDKG(request.Operators, request.SessionID, d.key)
	if err != nil {
		log.Error().Err(err).Msg("error running DKG")
		return api.SignResponse{}, err
	}

	// blow up if any nodes failed to qualify for the final group
	if len(result.QUAL) != len(request.Operators) {
		msg := "not all operators completed the DKG successfully"
		log.Error().Msg(msg)
		return api.SignResponse{}, errors.New(msg)
	}

	// sign the deposit data using the key share
	partialSignature, err := d.thresholdScheme.SignWithPartial(result.Key.Share, request.Data)
	if err != nil {
		log.Error().Err(err).Msg("error signing deposit data")
		return api.SignResponse{}, err
	}

	// encrypt the key share for use by the SSV node later via smart contract
	distKeyBytes, err := crypto.MarshalDistKey(result.Key.Share)
	if err != nil {
		log.Error().Err(err).Msg("error marshalling key share")
		return api.SignResponse{}, err
	}
	encryptedShare, err := d.encryptionScheme.Encrypt(validatorIdentity.PublicKey, distKeyBytes)
	if err != nil {
		log.Error().Err(err).Msg("error encrypting key share")
		return api.SignResponse{}, err
	}

	// encrypt the validator nonce
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, validatorIdentity.Nonce)
	encryptedNonce, err := d.encryptionScheme.Encrypt(validatorIdentity.PublicKey, buf)
	if err != nil {
		log.Error().Err(err).Msg("error encrypting nonce")
		return api.SignResponse{}, err
	}

	groupPublicKey, err := result.Key.Public().MarshalBinary()
	if err != nil {
		log.Error().Err(err).Msg("error marshalling public key")
		return api.SignResponse{}, err
	}

	publicPolynomial := share.NewPubPoly(d.thresholdScheme.KeyGroup(), result.Key.Public(), result.Key.Commits)
	publicBytes, err := crypto.MarshalPubPoly(publicPolynomial)
	if err != nil {
		log.Error().Err(err).Msg("error marshalling public polynomial")
		return api.SignResponse{}, err
	}

	log.Info().Msgf("DKG with sessionID %s completed successfully", hex.EncodeToString(request.SessionID))

	return api.SignResponse{
		SharePK:                        groupPublicKey,
		ValidatorPK:                    publicBytes,
		DepositDataPartialSignature:    partialSignature,
		EncryptedShare:                 encryptedShare,
		DepositValidatorNonceSignature: encryptedNonce,
	}, nil
}

func (d Daemon) Identity() (api.SidecarIdentityResponse, error) {
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
	d.dkg.ProcessPacket(packet)
	return nil
}
