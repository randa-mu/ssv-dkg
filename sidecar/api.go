package sidecar

import (
	"encoding/binary"
	"github.com/go-chi/chi/v5"
	"github.com/randa-mu/ssv-dkg/shared/api"
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
	// sign it using the "distributed key"
	signature, err := d.thresholdScheme.Sign(d.key, request.Data)
	if err != nil {
		log.Error().Err(err).Msg("error signing deposit data")
		return api.SignResponse{}, err
	}

	// fetch the public key of the SSV node
	validatorIdentity, err := d.ssvClient.Identity()
	if err != nil {
		log.Error().Err(err).Msg("error fetching SSV node public key")
		return api.SignResponse{}, err
	}

	// encrypt the 'share' (in this case some junk)
	encryptedShare, err := d.encryptionScheme.Encrypt(validatorIdentity.PublicKey, []byte("deadbeef"))
	if err != nil {
		log.Error().Err(err).Msg("error encrypting share")
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

	return api.SignResponse{
		SharePK:                        d.key.Public,
		ValidatorPK:                    validatorIdentity.PublicKey,
		DepositDataPartialSignature:    signature,
		EncryptedShare:                 encryptedShare,
		DepositValidatorNonceSignature: encryptedNonce,
	}, nil
}
