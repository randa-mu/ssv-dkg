package api

import (
	"github.com/drand/kyber"
	"github.com/drand/kyber/share/dkg"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestConversionOfDealPackets(t *testing.T) {
	scheme := crypto.NewBLSSuite()
	rand := (&crypto.SchnorrSuite{Group: scheme.KeyGroup()}).RandomStream()
	bundle := dkg.DealBundle{
		DealerIndex: 1,
		Deals: []dkg.Deal{{
			ShareIndex:     0,
			EncryptedShare: []byte("deadbeef"),
		}, {
			ShareIndex:     1,
			EncryptedShare: []byte("abcabcabc"),
		}},
		Public:    []kyber.Point{scheme.KeyGroup().Point().Pick(rand), scheme.KeyGroup().Point().Pick(rand)},
		SessionID: []byte("cafebabe"),
		Signature: []byte("f00f00f00"),
	}

	deal, err := DealFromDomain(&bundle)
	require.NoError(t, err)

	createdBundle, err := deal.ToDomain(scheme)
	require.NoError(t, err)
	require.Equal(t, bundle.Hash(), createdBundle.Hash())
}

func TestConversionOfJustificationPackets(t *testing.T) {
	scheme := crypto.NewBLSSuite()

	bundle := dkg.JustificationBundle{
		DealerIndex: 2,
		Justifications: []dkg.Justification{{
			ShareIndex: 0,
			Share:      scheme.KeyGroup().Scalar().Zero(),
		}, {
			ShareIndex: 1,
			Share:      scheme.KeyGroup().Scalar().One(),
		}},
		SessionID: []byte("cafebabe"),
		Signature: []byte("f00f00f00"),
	}

	justification, err := JustFromDomain(&bundle)
	require.NoError(t, err)
	createdJustification, err := justification.ToDomain(scheme)
	require.NoError(t, err)
	require.Equal(t, bundle.Hash(), createdJustification.Hash())
}
