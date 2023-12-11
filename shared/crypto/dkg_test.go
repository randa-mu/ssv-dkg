package crypto

import (
	"github.com/drand/kyber/share"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestMarshallingCommitments(t *testing.T) {
	scheme := NewBLSSuite()
	rand := scheme.suite.RandomStream()

	s := scheme.KeyGroup().Scalar().Pick(rand)
	priv := share.NewPriPoly(scheme.KeyGroup(), 2, s, rand)
	pub := priv.Commit(scheme.KeyGroup().Point().Base())

	bytes, err := MarshalPubPoly(pub)
	require.NoError(t, err)
	reconstructed, err := UnmarshalPubPoly(scheme, bytes)
	require.NoError(t, err)

	require.True(t, pub.Equal(&reconstructed))
}

func TestMarshallingDistKey(t *testing.T) {
	scheme := NewBLSSuite()
	rand := scheme.suite.RandomStream()

	s := scheme.KeyGroup().Scalar().Pick(rand)
	priv := share.NewPriPoly(scheme.KeyGroup(), 2, s, rand)
	shares := priv.Shares(2)

	bytes1, err := MarshalDistKey(shares[0])
	require.NoError(t, err)
	reconstructed1, err := UnmarshalDistKey(scheme, bytes1)
	require.NoError(t, err)
	require.Equal(t, shares[0].Hash(scheme.suite), reconstructed1.Hash(scheme.suite))

	bytes2, err := MarshalDistKey(shares[1])
	require.NoError(t, err)
	reconstructed2, err := UnmarshalDistKey(scheme, bytes2)
	require.NoError(t, err)
	require.Equal(t, shares[1].Hash(scheme.suite), reconstructed2.Hash(scheme.suite))
}
