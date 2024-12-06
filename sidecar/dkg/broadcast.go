package dkg

import (
	"fmt"
	"sync"

	"golang.org/x/exp/slog"

	"github.com/drand/kyber/share/dkg"

	"github.com/randa-mu/ssv-dkg/shared/api"
)

type DKGBoard struct {
	lock           sync.Mutex
	senders        []string
	packetsSeen    map[string]bool
	deals          chan dkg.DealBundle
	responses      chan dkg.ResponseBundle
	justifications chan dkg.JustificationBundle
}

func NewDKGBoard(senders []string) *DKGBoard {
	// we have filtered out our own address by senders
	// but we actually receive a packet for ourself on each of these channels,
	// so the capacity needs to be +1 or the channel listen will last forever
	totalPackets := len(senders) + 1
	return &DKGBoard{
		senders:        senders,
		deals:          make(chan dkg.DealBundle, totalPackets),
		responses:      make(chan dkg.ResponseBundle, totalPackets),
		justifications: make(chan dkg.JustificationBundle, totalPackets),
		packetsSeen:    make(map[string]bool),
	}
}

func (d *DKGBoard) PushDeals(bundle *dkg.DealBundle) {
	d.lock.Lock()
	defer d.lock.Unlock()

	h := bundle.Hash()
	hash := string(h)
	if d.packetsSeen[hash] {
		slog.Debug("ignoring duplicate DKG packet")
		return
	}
	d.packetsSeen[hash] = true

	d.deals <- *bundle

	dealPacket, err := api.DealFromDomain(bundle)
	if err != nil {
		slog.Error(fmt.Sprintf("couldn't construct a deal packet to gossip from %d", bundle.DealerIndex), err)
	} else {
		d.gossip(api.SidecarDKGPacket{Deal: dealPacket})
	}
}

func (d *DKGBoard) PushResponses(bundle *dkg.ResponseBundle) {
	d.lock.Lock()
	defer d.lock.Unlock()

	hash := string(bundle.Hash())
	if d.packetsSeen[hash] {
		slog.Debug("ignoring duplicate DKG packet")
		return
	}
	d.packetsSeen[hash] = true

	d.responses <- *bundle
	d.gossip(api.SidecarDKGPacket{Response: &api.Response{ResponseBundle: *bundle}})
}

func (d *DKGBoard) PushJustifications(bundle *dkg.JustificationBundle) {
	d.lock.Lock()
	defer d.lock.Unlock()

	hash := string(bundle.Hash())
	if d.packetsSeen[hash] {
		slog.Debug("ignoring duplicate DKG packet")
		return
	}
	d.packetsSeen[hash] = true

	d.justifications <- *bundle

	justificationPacket, err := api.JustFromDomain(bundle)
	if err != nil {
		slog.Error(fmt.Sprintf("couldn't construct a justification packet to gossip from %d", bundle.DealerIndex), err)
	} else {
		d.gossip(api.SidecarDKGPacket{Justification: justificationPacket})
	}
}

func (d *DKGBoard) IncomingDeal() <-chan dkg.DealBundle {
	return d.deals
}

func (d *DKGBoard) IncomingResponse() <-chan dkg.ResponseBundle {
	return d.responses
}

func (d *DKGBoard) IncomingJustification() <-chan dkg.JustificationBundle {
	return d.justifications
}

func (d *DKGBoard) gossip(packet api.SidecarDKGPacket) {
	slog.Debug("gossiping DKG packets", "to", d.senders)
	for _, s := range d.senders {
		go func(s string) {
			client := api.NewSidecarClient(s)
			err := client.BroadcastDKG(packet)
			if err != nil {
				slog.Error(fmt.Sprintf("error writing DKG packet to %s", s), "err", err)
			}
		}(s)
	}
}
