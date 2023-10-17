package crypto

import (
	"github.com/stretchr/testify/require"
	"testing"
)

var suite Suite

func TestKeyCryptography(t *testing.T) {
	suites := []Suite{NewRSASuite(), NewBLSSuite()}

	for _, s := range suites {
		suite = s
		t.Run("creating a key, signing it, and verifying the self-sign", CreatingAKeyAndSigningItAndVerifyingIt)
		t.Run("verifying an invalid self-signature fails", CreatingAKeyAndSigningItAndModifyingTheSignature)
		t.Run("verifying a valid self-signature with the wrong key fails", CreatingKeyAndSigningItAndModifyingKey)
		t.Run("signing arbitary bytes can be verified", KeypairSigningArbitraryBytesVerifies)
		t.Run("invalid message fails for signature", InvalidMessageFailsForSignature)
	}
}

func CreatingAKeyAndSigningItAndVerifyingIt(t *testing.T) {
	t.Parallel()

	k, err := suite.CreateKeypair()
	require.NoError(t, err)

	i, err := k.SelfSign(suite, "hello world")
	require.NoError(t, err)

	require.NoError(t, i.Verify(suite))
}

func CreatingAKeyAndSigningItAndModifyingTheSignature(t *testing.T) {
	t.Parallel()

	k, err := suite.CreateKeypair()
	require.NoError(t, err)

	i, err := k.SelfSign(suite, "hello world")
	require.NoError(t, err)

	i.Signature = []byte("deadbeef")

	require.Error(t, i.Verify(suite))
}

func CreatingKeyAndSigningItAndModifyingKey(t *testing.T) {
	t.Parallel()

	k, err := suite.CreateKeypair()
	require.NoError(t, err)

	i, err := k.SelfSign(suite, "hello world")
	require.NoError(t, err)

	i.Public = []byte("deadbeef")

	require.Error(t, i.Verify(suite))
}

func KeypairSigningArbitraryBytesVerifies(t *testing.T) {
	t.Parallel()

	m := []byte("deadbeef")
	k, err := suite.CreateKeypair()
	require.NoError(t, err)

	sig, err := suite.Sign(k, m)
	require.NoError(t, err)

	require.NoError(t, suite.Verify(m, k.Public, sig))
}

func InvalidMessageFailsForSignature(t *testing.T) {
	t.Parallel()

	m := []byte("deadbeef")
	k, err := suite.CreateKeypair()
	require.NoError(t, err)

	sig, err := suite.Sign(k, m)
	require.NoError(t, err)

	require.Error(t, suite.Verify([]byte("different message"), k.Public, sig))
}
