package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/netrack/openflow/ofp"
	log "github.com/sirupsen/logrus"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

type Supplicant struct {
	Id              uint8
	Username        string
	State           []byte
	HardwareAddress net.HardwareAddr

	RadiusRequestQueue chan *AugmentedRadiusPacket
	Destroy            chan byte
}

func (app *App) getNextEapPacketId() byte {
	app.eapPacketId += 1
	return app.eapPacketId
}

// Processes OpenFlow packet in messages
func (app *App) SupplicantPacketProcessor() {
	var message *OpenFlowPacketInMessage
	var err error

	for {
		message = <-app.packetInQueue
		log.
			WithFields(log.Fields{
				"context":   message.Context.String(),
				"header":    message.Header,
				"packet_in": fmt.Sprintf("%02x", message.PacketIn.Data),
			}).
			Error("Processing OF-PACKET-IN")

		// Decode the packet
		packet := gopacket.NewPacket(message.PacketIn.Data, layers.LayerTypeEthernet, gopacket.Default)

		// Decode EAPOL, if not EAPOL then we are not interested
		if packet.Layer(layers.LayerTypeEAPOL) == nil {
			names := make([]string, len(packet.Layers()))
			for i, layer := range packet.Layers() {
				names[i] = layer.LayerType().String()
			}
			log.
				WithFields(log.Fields{
					"layers": names,
				}).
				Error("Non-EAPOL packet is unexpected, ignoring")
			continue
		}

		// Decode the layers in which we are interested
		eth := layers.Ethernet{}
		eapol := layers.EAPOL{}

		err = eth.DecodeFromBytes(packet.LinkLayer().LayerContents(), nil)
		if err != nil {
			log.WithError(err).Error("Unable to decode ethernet layer")
			continue
		}

		err = eapol.DecodeFromBytes(packet.Layer(layers.LayerTypeEAPOL).LayerContents(), nil)
		if err != nil {
			log.WithError(err).Error("Unable to decode ethernet layer")
			continue
		}

		log.
			WithFields(log.Fields{
				"eapol type": eapol.Type.String(),
			}).
			Debug("EAPOL type received")
		switch eapol.Type {

		// If an EAPOL start is received then an IDENTITY request is
		// sent to the supplicant
		case layers.EAPOLTypeStart:

			// If we have a start then if a record is not yet
			// created for this client, then create one and then
			// packet out to them a request for identity
			sup, ok := app.supplicants[eth.SrcMAC.String()]
			if !ok {
				sup = &Supplicant{
					Id:                 getId(),
					RadiusRequestQueue: make(chan *AugmentedRadiusPacket, 10),
					Destroy:            make(chan byte, 1),
					HardwareAddress:    eth.SrcMAC,
				}
				app.supplicants[eth.SrcMAC.String()] = sup
				go sup.SupplicantRadiusRequestsSender(app.RadiusAt, app.radiusResponseQueue, app.RadiusTimeout)

				log.
					WithFields(log.Fields{
						"supplicant": eth.SrcMAC.String(),
					}).
					Debug("START: Creating supplicant record")
			} else {
				log.
					WithFields(log.Fields{
						"supplicant": eth.SrcMAC.String(),
					}).
					Debug("START: Found supplicant record")
			}

			// Emit an identity request to the supplicant
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{}
			gopacket.SerializeLayers(buf, opts,
				&layers.Ethernet{
					SrcMAC:       net.HardwareAddr{0xc0, 0xff, 0xee, 0xc0, 0xff, 0xee},
					DstMAC:       sup.HardwareAddress,
					EthernetType: layers.EthernetTypeEAPOL,
					Length:       0,
				},
				&layers.EAPOL{
					Version: eapol.Version,
					Type:    layers.EAPOLTypeEAP,
					Length:  5,
				},
				&layers.EAP{
					Id:       app.getNextEapPacketId(),
					Type:     layers.EAPTypeIdentity,
					Code:     layers.EAPCodeRequest,
					Length:   5,
					TypeData: []byte{0},
				})

			if log.GetLevel() >= log.DebugLevel {
				log.
					WithFields(log.Fields{
						"len":    len(buf.Bytes()),
						"packet": fmt.Sprintf("%02x", buf.Bytes()),
					}).
					Debug("Emit IDENTITY request to supplicant")
			}
			app.emit(message.Context.DatapathID, ofp.PortNo(message.Context.Port), buf.Bytes())

		// If an EAP was sent by the supplicant then we need look at the
		// type of EAP and decide what to do
		case layers.EAPOLTypeEAP:

			// Look up supplicant record
			sup, ok := app.supplicants[eth.SrcMAC.String()]
			if !ok {
				log.
					WithFields(log.Fields{
						"supplicant": eth.SrcMAC.String(),
					}).
					Error("No supplicant record found")
				continue
			}

			eap := &layers.EAP{}
			err = eap.DecodeFromBytes(packet.Layer(layers.LayerTypeEAP).LayerContents(), nil)
			if err != nil {
				log.WithError(err).Error("Unable to decode ethernet layer")
				continue
			}

			log.
				WithFields(log.Fields{
					"type": EapTypeToString(eap.Type),
				}).
				Debug("EAP type received")

			switch eap.Type {
			case layers.EAPTypeNACK:
			case layers.EAPTypeOTP:
				// app.processEapOtpPacket(message, &eth, &eapol, eap, packet)
				// continue
				rad := radius.New(radius.CodeAccessRequest, []byte(app.SharedSecret))
				rad.Identifier = app.getNextRadiusPacketId()
				rfc2865.UserName_SetString(rad, sup.Username)
				rfc2865.State_Set(rad, sup.State)
				rad.Set(EAPMessage, packet.Layer(layers.LayerTypeEAP).LayerContents())

				app.EncodeAndSend(&AugmentedRadiusPacket{
					Supplicant:   sup,
					EAPOLVersion: eapol.Version,
					Context:      message.Context,
					Packet:       rad,
				})
			case layers.EAPTypeNone:
			case layers.EAPTypeTokenCard:
			case layers.EAPTypeNotification:
			case layers.EAPTypeIdentity:
				log.
					WithFields(log.Fields{
						"username": string(eap.TypeData),
					}).
					Debug("Supplicant identity")

				// With the supplicant username, a packet can
				// now be sent to the radius server. First,
				// capture information to the supplicant
				// record
				// sup.Id = eap.Id
				sup.Username = string(eap.TypeData)

				// Construct a RADIUS packet with encapsulated
				// EAP packet and a zero-ed authenticator. Use
				// this to calculate an MD5 hash and then
				// add the has as an authenticator
				rad := radius.New(radius.CodeAccessRequest, []byte(app.SharedSecret))
				rad.Identifier = app.getNextRadiusPacketId()
				rfc2865.UserName_SetString(rad, sup.Username)
				rad.Add(EAPMessage, packet.Layer(layers.LayerTypeEAP).LayerContents())

				app.EncodeAndSend(&AugmentedRadiusPacket{
					Supplicant:   sup,
					EAPOLVersion: eapol.Version,
					Context:      message.Context,
					Packet:       rad,
				})
			}
		case layers.EAPOLTypeKey:
			log.
				WithFields(log.Fields{
					"state": "***** EAPOL KEY",
				}).
				Debug("received")
		case layers.EAPOLTypeLogOff:
			log.
				WithFields(log.Fields{
					"state": "***** EAPOL LOGOFF",
				}).
				Debug("received")
		default:
			log.
				WithFields(log.Fields{
					"state": fmt.Sprintf("***** EAPOL %s", eapol.Type.String()),
				}).
				Debug("received")
		}
	}
}

func (sup *Supplicant) SupplicantRadiusRequestsSender(AddressOfRadiusServer string, RadiusResponseQueue chan<- *AugmentedRadiusPacket, RequestTimeOut time.Duration) {
	var request *AugmentedRadiusPacket
	var response *radius.Packet
	var err error

	for {
		err = nil
		select {
		case <-sup.Destroy:
			return
		case request = <-sup.RadiusRequestQueue:
			if log.GetLevel() >= log.DebugLevel {
				encode, _ := request.Packet.Encode()
				log.
					WithFields(log.Fields{
						"code":       request.Packet.Code.String(),
						"attributes": request.Packet.Attributes,
						"request":    fmt.Sprintf("%02x", encode),
					}).
					Debug("Sending to RADIUS")
			}
			ctx, _ := context.WithTimeout(context.Background(), RequestTimeOut)
			response, err = radius.Exchange(ctx, request.Packet, AddressOfRadiusServer)
			ctx.Done()
			if err != nil {
				encode, _ := request.Packet.Encode()
				log.
					WithError(err).
					WithFields(log.Fields{
						"code":       request.Packet.Code.String(),
						"attributes": request.Packet.Attributes,
						"request":    fmt.Sprintf("%02x", encode),
					}).
					Error("Error sending request to RADIUS")
				continue
			}

			if log.GetLevel() >= log.DebugLevel {
				encode, _ := response.Encode()
				log.
					WithFields(log.Fields{
						"code":       response.Code.String(),
						"attributes": response.Attributes,
						"request":    fmt.Sprintf("%02x", encode),
					}).
					Debug("Queuing RADIUS response for processing")
			}

			RadiusResponseQueue <- &AugmentedRadiusPacket{
				Supplicant:   sup,
				EAPOLVersion: request.EAPOLVersion,
				Context:      request.Context,
				Packet:       response,
			}
		}
	}
}
