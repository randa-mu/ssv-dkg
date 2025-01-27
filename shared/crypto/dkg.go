package crypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/drand/kyber"
	"github.com/drand/kyber/share"
)

func MarshalDistKey(key *share.PriShare) ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.BigEndian, uint64(key.I)); err != nil {
		return nil, err
	}

	b, err := key.V.MarshalBinary()
	if err != nil {
		return nil, err
	}

	if err = binary.Write(buf, binary.BigEndian, b); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func UnmarshalDistKey(scheme ThresholdScheme, bytes []byte) (share.PriShare, error) {
	if len(bytes) < 8 {
		return share.PriShare{}, errors.New("invalid length for dist key")
	}
	I := binary.BigEndian.Uint64(bytes[0:8])

	V := scheme.KeyGroup().Scalar()
	if err := V.UnmarshalBinary(bytes[8:]); err != nil {
		return share.PriShare{}, err
	}
	return share.PriShare{
		I: int(I),
		V: V,
	}, nil
}

func DistKeyWithoutIndex(bytes []byte) []byte {
	return bytes[8:]
}

func MarshalPubPoly(pub *share.PubPoly) ([]byte, error) {
	buf := new(bytes.Buffer)

	_, commits := pub.Info()

	for _, commit := range commits {
		commitBytes, err := commit.MarshalBinary()
		if err != nil {
			return nil, err
		}
		err = binary.Write(buf, binary.BigEndian, commitBytes)
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func UnmarshalPubPoly(scheme ThresholdScheme, b []byte) (share.PubPoly, error) {
	group := scheme.KeyGroup()
	pointLen := group.PointLen()
	base := group.Point()

	l := len(b)
	if l == 0 || l%pointLen != 0 {
		return share.PubPoly{}, fmt.Errorf("invalid length for public polynomial; expected multiple of %d, got %d (remainder %d)", pointLen, l, l%pointLen)
	}

	var err error
	var commits []kyber.Point
	for i := 0; i+pointLen <= l; i += pointLen {
		p := group.Point()
		err = p.UnmarshalBinary(b[i : i+pointLen])
		if err != nil {
			return share.PubPoly{}, err
		}
		commits = append(commits, p)
	}

	return *share.NewPubPoly(group, base, commits), nil
}

func ExtractGroupPublicKey(scheme ThresholdScheme, publicPolynomial []byte) []byte {
	return publicPolynomial[0:scheme.KeyGroup().PointLen()]
}
