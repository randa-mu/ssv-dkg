package crypto

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCreatingAKeyAndSigningItAndVerifyingIt(t *testing.T) {
	t.Parallel()

	k, err := CreateKeypair()
	require.NoError(t, err)

	i, err := k.SelfSign("hello world")
	require.NoError(t, err)

	require.NoError(t, i.Verify())
}

func TestCreatingAKeyAndSigningItAndModifyingTheSignature(t *testing.T) {
	t.Parallel()

	k, err := CreateKeypair()
	require.NoError(t, err)

	i, err := k.SelfSign("hello world")
	require.NoError(t, err)

	i.Signature = []byte("deadbeef")

	require.Error(t, i.Verify())
}

func TestCreatingKeyAndSigningItAndModifyingKey(t *testing.T) {
	t.Parallel()

	k, err := CreateKeypair()
	require.NoError(t, err)

	i, err := k.SelfSign("hello world")
	require.NoError(t, err)

	i.Public = []byte("deadbeef")

	require.Error(t, i.Verify())
}

func TestKeypairSigningArbitraryBytesVerifies(t *testing.T) {
	t.Parallel()

	m := []byte("deadbeef")
	k, err := CreateKeypair()
	require.NoError(t, err)

	sig, err := k.Sign(m)
	require.NoError(t, err)

	require.NoError(t, VerifySignature(m, k.Public, sig))
}

func TestInvalidMessageFailsForSignature(t *testing.T) {
	t.Parallel()

	m := []byte("deadbeef")
	k, err := CreateKeypair()
	require.NoError(t, err)

	sig, err := k.Sign(m)
	require.NoError(t, err)

	require.Error(t, VerifySignature([]byte("different message"), k.Public, sig))
}
