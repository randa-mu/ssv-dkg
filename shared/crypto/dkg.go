package crypto

import (
	"bytes"
	"encoding/binary"
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

func MarshalPubPoly(pub *share.PubPoly) ([]byte, error) {
	buf := new(bytes.Buffer)

	base, commits := pub.Info()
	baseBytes, err := base.MarshalBinary()
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.BigEndian, baseBytes)
	if err != nil {
		return nil, err
	}

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
	err := base.UnmarshalBinary(b[0:pointLen])
	if err != nil {
		return share.PubPoly{}, err
	}
	var commits []kyber.Point
	for i := pointLen; i < len(b); i += pointLen {
		p := group.Point()
		err = p.UnmarshalBinary(b[i : i+pointLen])
		if err != nil {
			return share.PubPoly{}, err
		}
		commits = append(commits, p)
	}

	return *share.NewPubPoly(group, base, commits), nil
}
