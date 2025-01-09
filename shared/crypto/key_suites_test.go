package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/drand/kyber/share"
)

var scheme SigningScheme

func TestSigning(t *testing.T) {
	schemes := []SigningScheme{NewRSASuite(), NewBLSSuite()}

	for _, s := range schemes {
		scheme = s
		t.Run("creating a key, signing it, and verifying the self-sign", CreatingAKeyAndSigningItAndVerifyingIt)
		t.Run("verifying an invalid self-signature fails", CreatingAKeyAndSigningItAndModifyingTheSignature)
		t.Run("incorrect operatorID fails verification", InvalidOperatorIdFailsVerification)
		t.Run("verifying a valid self-signature with the wrong key fails", CreatingKeyAndSigningItAndModifyingKey)
		t.Run("signing arbitrary bytes can be verified", KeypairSigningArbitraryBytesVerifies)
		t.Run("invalid message fails for signature", InvalidMessageFailsForSignature)
	}
}

func TestEncryption(t *testing.T) {
	t.Parallel()
	scheme := NewRSASuite()

	kp, err := scheme.CreateKeypair()
	require.NoError(t, err)

	plaintext := []byte("hello world")
	ciphertext, err := scheme.Encrypt(kp.Public, plaintext)
	require.NoError(t, err)

	p, err := scheme.Decrypt(kp.Private, ciphertext)
	require.NoError(t, err)

	require.Equal(t, plaintext, p)
}

func TestThresholdSchemePartialSigning(t *testing.T) {
	scheme := NewBLSSuite()
	rand := scheme.suite.RandomStream()
	message := []byte("hello world")

	s := scheme.KeyGroup().Scalar().Pick(rand)
	priv := share.NewPriPoly(scheme.KeyGroup(), 2, s, rand)
	pub := priv.Commit(scheme.KeyGroup().Point().Base())

	shares := priv.Shares(2)
	distKey1, err := MarshalDistKey(shares[0])
	require.NoError(t, err)
	signature1, err := scheme.SignWithPartial(distKey1, message)
	require.NoError(t, err)

	distKey2, err := MarshalDistKey(shares[1])
	require.NoError(t, err)
	signature2, err := scheme.SignWithPartial(distKey2, message)
	require.NoError(t, err)

	pubKey, err := MarshalPubPoly(pub)
	require.NoError(t, err)

	err = scheme.VerifyPartial(pubKey, message, signature1)
	require.NoError(t, err)
	err = scheme.VerifyPartial(pubKey, message, signature2)
	require.NoError(t, err)
}

func CreatingAKeyAndSigningItAndVerifyingIt(t *testing.T) {
	t.Parallel()

	k, err := scheme.CreateKeypair()
	require.NoError(t, err)

	i, err := k.SelfSign(scheme, "hello world", 1)
	require.NoError(t, err)

	require.NoError(t, i.Verify(scheme))
}

func CreatingAKeyAndSigningItAndModifyingTheSignature(t *testing.T) {
	t.Parallel()

	k, err := scheme.CreateKeypair()
	require.NoError(t, err)

	i, err := k.SelfSign(scheme, "hello world", 1)
	require.NoError(t, err)

	i.Signature = []byte("deadbeef")

	require.Error(t, i.Verify(scheme))
}

func CreatingKeyAndSigningItAndModifyingKey(t *testing.T) {
	t.Parallel()

	k, err := scheme.CreateKeypair()
	require.NoError(t, err)

	i, err := k.SelfSign(scheme, "hello world", 1)
	require.NoError(t, err)

	i.Public = []byte("deadbeef")

	require.Error(t, i.Verify(scheme))
}

func KeypairSigningArbitraryBytesVerifies(t *testing.T) {
	t.Parallel()

	m := []byte("deadbeef")
	k, err := scheme.CreateKeypair()
	require.NoError(t, err)

	sig, err := scheme.Sign(k, m)
	require.NoError(t, err)

	require.NoError(t, scheme.Verify(m, k.Public, sig))
}

func InvalidMessageFailsForSignature(t *testing.T) {
	t.Parallel()

	m := []byte("deadbeef")
	k, err := scheme.CreateKeypair()
	require.NoError(t, err)

	sig, err := scheme.Sign(k, m)
	require.NoError(t, err)

	require.Error(t, scheme.Verify([]byte("different message"), k.Public, sig))
}

func InvalidOperatorIdFailsVerification(t *testing.T) {
	t.Parallel()

	k, err := scheme.CreateKeypair()
	require.NoError(t, err)

	i, err := k.SelfSign(scheme, "hello world", 1)
	require.NoError(t, err)

	i.OperatorID = 2

	require.Error(t, i.Verify(scheme))
}
