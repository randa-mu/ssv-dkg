package api

import (
	"github.com/drand/kyber"
	"github.com/drand/kyber/share/dkg"
	"github.com/randa-mu/ssv-dkg/shared/crypto"
)

type SidecarDKGPacket struct {
	Deal          *Deal
	Response      *Response
	Justification *Justification
}

type Deal struct {
	DealerIndex uint32
	Deals       []dkg.Deal
	Public      [][]byte
	SessionID   []byte
	Signature   []byte
}

type Response struct {
	dkg.ResponseBundle
}

type Justification struct {
	DealerIndex    uint32
	Justifications []JustificationShare
	SessionID      []byte
	Signature      []byte
}

type JustificationShare struct {
	ShareIndex uint32
	Share      []byte
}

// ToDomain takes the deal part of an HTTP request and maps it into
// a type usable by the kyber DKG
func (d Deal) ToDomain(scheme crypto.ThresholdScheme) (dkg.DealBundle, error) {
	publicCommitments := make([]kyber.Point, len(d.Public))
	for i, p := range d.Public {
		point := scheme.KeyGroup().Point()
		err := point.UnmarshalBinary(p)
		if err != nil {
			return dkg.DealBundle{}, err
		}

		publicCommitments[i] = point
	}

	return dkg.DealBundle{
		DealerIndex: d.DealerIndex,
		Deals:       d.Deals,
		Public:      publicCommitments,
		SessionID:   d.SessionID,
		Signature:   d.Signature,
	}, nil
}

// DealFromDomain takes the kyber DKG packet and turns it into something
// that can be marshalled into an HTTP request
func DealFromDomain(bundle *dkg.DealBundle) (*Deal, error) {
	publicCommitments := make([][]byte, len(bundle.Public))
	for i, p := range bundle.Public {
		bytes, err := p.MarshalBinary()
		if err != nil {
			return nil, err
		}

		publicCommitments[i] = bytes
	}

	return &Deal{
		DealerIndex: bundle.DealerIndex,
		Deals:       bundle.Deals,
		Public:      publicCommitments,
		SessionID:   bundle.SessionID,
		Signature:   bundle.Signature,
	}, nil
}

// ToDomain takes the deal part of an HTTP request and maps it into
// a type usable by the kyber DKG
func (j Justification) ToDomain(scheme crypto.ThresholdScheme) (dkg.JustificationBundle, error) {
	justifs := make([]dkg.Justification, len(j.Justifications))
	for i, it := range j.Justifications {
		s := scheme.KeyGroup().Scalar()
		err := s.UnmarshalBinary(it.Share)
		if err != nil {
			return dkg.JustificationBundle{}, err
		}

		justifs[i] = dkg.Justification{
			ShareIndex: it.ShareIndex,
			Share:      s,
		}
	}

	return dkg.JustificationBundle{
		DealerIndex:    j.DealerIndex,
		Justifications: justifs,
		SessionID:      j.SessionID,
		Signature:      j.Signature,
	}, nil
}

// JustFromDomain takes the kyber DKG packet and turns it into something
// that can be marshalled into an HTTP request
func JustFromDomain(bundle *dkg.JustificationBundle) (*Justification, error) {
	justifs := make([]JustificationShare, len(bundle.Justifications))
	for i, it := range bundle.Justifications {
		share, err := it.Share.MarshalBinary()
		if err != nil {
			return nil, err
		}
		justifs[i] = JustificationShare{
			ShareIndex: it.ShareIndex,
			Share:      share,
		}
	}
	return &Justification{
		DealerIndex:    bundle.DealerIndex,
		Justifications: justifs,
		SessionID:      bundle.SessionID,
		Signature:      bundle.Signature,
	}, nil
}
