package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/netrack/openflow/ofp"
	log "github.com/sirupsen/logrus"
	"layeh.com/radius/rfc2865"
)

func (app *App) getNextRadiusPacketId() byte {
	app.radiusPacketId += 1
	return app.radiusPacketId
}

// Process responses from the RADIUS server
func (app *App) RadiusResponseProcessor() {
	var response *AugmentedRadiusPacket
	var eapBytes []byte
	var err error

	for {
		response = <-app.radiusResponseQueue
		if log.GetLevel() >= log.DebugLevel {
			encode, _ := response.Packet.Encode()
			log.
				WithFields(log.Fields{
					"code":       response.Packet.Code.String(),
					"attributes": response.Packet.Attributes,
					"response":   fmt.Sprintf("%02x", encode),
				}).
				Debug("Process RADIUS response")
		}

		eapBytes = response.Packet.Get(EAPMessage)
		if eapBytes == nil {
			log.Error("Radius response did not container EAP, ignoring")
			continue
		}

		// Save the supplicant state
		response.Supplicant.State = rfc2865.State_Get(response.Packet)

		// We have a response with a bundled EAP packet,
		// now to emit that back to the suplicant
		eap := &layers.EAP{}
		err = eap.DecodeFromBytes(eapBytes, nil)
		if err != nil {
			log.
				WithError(err).
				Error("NO DECODE FOR YOU")
			continue
		}

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{}
		gopacket.SerializeLayers(buf, opts,
			&layers.Ethernet{
				SrcMAC:       net.HardwareAddr{0xc0, 0xff, 0xee, 0xc0, 0xff, 0xee},
				DstMAC:       response.Supplicant.HardwareAddress,
				EthernetType: layers.EthernetTypeEAPOL,
				Length:       0,
			},
			&layers.EAPOL{
				Version: response.EAPOLVersion,
				Type:    layers.EAPOLTypeEAP,
				Length:  eap.Length,
			},
			eap)

		if log.GetLevel() >= log.DebugLevel {
			log.
				WithFields(log.Fields{
					"code": response.Packet.Code.String(),
					"len":  len(buf.Bytes()),
					"data": fmt.Sprintf("%02x", buf.Bytes()),
				}).
				Debug("Sending to supplicant")
		}
		app.emit(response.Context.DatapathID, ofp.PortNo(response.Context.Port), buf.Bytes())
	}
}
