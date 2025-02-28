package crypto

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/herumi/bls-eth-go-binary/bls"
	spectypes "github.com/ssvlabs/ssv-spec/types"
	"github.com/ssvlabs/ssv/protocol/v2/ssv"
	"github.com/ssvlabs/ssv/utils/threshold"
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
	require.NoError(t, bls.Init(bls.BLS12_381))

	scheme := NewBLSSuite()
	rand := scheme.suite.RandomStream()
	// keccak-256 to have a 32-byte message compatible with ssv's types
	message := crypto.Keccak256([]byte("hello world"))

	hb, err := hex.DecodeString("4aac41b5cb665b93e031faa751944b1f14d77cb17322403cba8df1d6e4541a4d")
	require.NoError(t, err)

	s := scheme.KeyGroup().Scalar().SetBytes(hb)
	priv := share.NewPriPoly(scheme.KeyGroup(), 3, s, rand)
	pub := priv.Commit(scheme.KeyGroup().Point().Base())

	shares := priv.Shares(4)
	distKey1, err := MarshalDistKey(shares[1])
	require.NoError(t, err)
	signature1, err := scheme.SignWithPartial(distKey1, message)
	require.NoError(t, err)

	distKey2, err := MarshalDistKey(shares[2])
	require.NoError(t, err)
	signature2, err := scheme.SignWithPartial(distKey2, message)
	require.NoError(t, err)

	distKey3, err := MarshalDistKey(shares[3])
	require.NoError(t, err)
	signature3, err := scheme.SignWithPartial(distKey3, message)
	require.NoError(t, err)

	pubKey, err := MarshalPubPoly(pub)
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%x", pubKey[:48]), "841c5235ec7f4eed02b3f3bb60622d3ed0aba74016f4850c6d7c962656a4b78d72a15caeef62dfe656d03990590c0026")

	err = scheme.VerifyPartial(pubKey, message, signature1)
	require.NoError(t, err)
	err = scheme.VerifyPartial(pubKey, message, signature2)
	require.NoError(t, err)
	err = scheme.VerifyPartial(pubKey, message, signature3)
	require.NoError(t, err)

	ps := ssv.NewPartialSigContainer(2)
	// this displays the index 1
	t.Log(signature1[:2])
	s1 := &spectypes.PartialSignatureMessage{
		PartialSignature: signature1[2:], // we need to remove the index
		SigningRoot:      [32]byte(message),
		Signer:           2, // and we need to use index 2 for it, nor 1!!!
		ValidatorIndex:   42,
	}
	// this displays the index 2...
	t.Log(signature2[:2])
	s2 := &spectypes.PartialSignatureMessage{
		PartialSignature: signature2[2:],
		SigningRoot:      [32]byte(message),
		Signer:           3, // and yet we need to use index 3 for it!
		ValidatorIndex:   42,
	}
	// this displays the index 3...
	t.Log(signature3[:2])
	s3 := &spectypes.PartialSignatureMessage{
		PartialSignature: signature3[2:],
		SigningRoot:      [32]byte(message),
		Signer:           4, // and yet we need to use index 4 for it!
		ValidatorIndex:   42,
	}
	ps.AddSignature(s1)
	ps.AddSignature(s2)
	ps.AddSignature(s3)
	_, err = ps.ReconstructSignature([32]byte(message), pubKey[:48], 42)
	require.NoError(t, err)
}

func TestSSVThresholdKeys(t *testing.T) {
	require.NoError(t, bls.Init(bls.BLS12_381))

	var sec bls.SecretKey
	secByte, _ := hex.DecodeString("4aac41b5cb665b93e031faa751944b1f14d77cb17322403cba8df1d6e4541a4d")
	require.NoError(t, sec.Deserialize(secByte))
	// keccak-256 to have a 32-byte message compatible with ssv's types
	msg := crypto.Keccak256([]byte("hello world"))
	pub := sec.GetPublicKey()
	skSig := sec.SignByte(msg)

	pk := &bls.PublicKey{}
	pb, err := hex.DecodeString("841c5235ec7f4eed02b3f3bb60622d3ed0aba74016f4850c6d7c962656a4b78d72a15caeef62dfe656d03990590c0026")
	require.NoError(t, err)
	require.NoError(t, pk.Deserialize(pb))
	require.Equal(t, pub.GetHexString(), pk.GetHexString())
	require.True(t, skSig.VerifyByte(pk, msg))

	privKeys, err := threshold.Create(sec.Serialize(), 3, 7)
	require.NoError(t, err)

	// partial sigs
	sigVec := make(map[uint64][]byte)
	sigArray := make([][]byte, 3)
	pubKeys := make([][]byte, 3)
	for i, s := range privKeys {
		if i >= 4 {
			continue
		}
		partialSig := s.SignByte(msg)
		sigVec[i] = partialSig.Serialize()
		sigArray[i-1] = partialSig.Serialize()
		pubKeys[i-1] = s.GetPublicKey().Serialize()
	}

	// reconstruct
	sig, _ := threshold.ReconstructSignatures(sigVec)
	require.True(t, skSig.IsEqual(sig))
	require.NoError(t, skSig.Deserialize(sig.Serialize()))
	require.True(t, sig.VerifyByte(sec.GetPublicKey(), msg))

	// now using kyber
	suite := NewBLSSuite()
	for i, _ := range pubKeys {
		t.Log("length", len(pubKeys[i]), len(sigVec[uint64(i+1)]), i, sigVec[uint64(i)+1])
		require.NoError(t, suite.Verify(msg, pubKeys[i], sigVec[uint64(i+1)]))
	}
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
