package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"fmt"
	"net/http"

	"github.com/netrack/openflow"
	"github.com/netrack/openflow/ofp"
	log "github.com/sirupsen/logrus"
	"layeh.com/radius/rfc2869"
)

// Creates an OpenFlow packet out message that encapsulates the given byte
// array as the packet out and sends it to the OFTEE for processing to the
// OpenFlow switch.
func (app *App) emit(dpid uint64, portNo ofp.PortNo, data []byte) {
	log.
		WithFields(log.Fields{
			"packet": fmt.Sprintf("%02x", data),
			"len":    len(data),
		}).
		Debug("OF-PACKET-OUT to switch")

	message := &bytes.Buffer{}
	packet := &bytes.Buffer{}

	// Create the packet out structure
	pktOut := ofp.PacketOut{
		Buffer:  ofp.NoBuffer,
		InPort:  ofp.PortAny,
		Actions: ofp.Actions{&ofp.ActionOutput{portNo, ofp.ContentLenNoBuffer}},
	}
	req := openflow.NewRequest(openflow.TypePacketOut, packet)
	pktOut.WriteTo(packet)
	packet.Write(data)

	// Encode the OF message to a byte array
	req.WriteTo(message)

	url := fmt.Sprintf("%s/oftee/0x%016x", app.OfTeeApi, dpid)
	log.
		WithFields(log.Fields{
			"url":      url,
			"openflow": fmt.Sprintf("%02x", message),
		}).
		Debug("Posting OF-PACKET-OUT to OFTEE")
	resp, err := http.Post(url, "application/octet-stream", message)
	if err != nil {
		log.
			WithFields(log.Fields{
				"url": url,
			}).
			WithError(err).
			Error("Failed to post OF-PACKET-OUT to OFTEE")
	} else if int(resp.StatusCode/100) != 2 {
		log.
			WithFields(log.Fields{
				"url":           url,
				"response-code": resp.StatusCode,
				"response":      resp.Status,
			}).
			Fatal("Non success code returned from oftee")
	}
}

// Generates and adds a RFC2869 authenticator HMAC.MD5 hash to the RADIUS
// packet and queue the request to send to RADIUS.
func (app *App) EncodeAndSend(request *AugmentedRadiusPacket) error {

	// Set the rfc 2869 authenticator to all zeros to generate the HMAC.MD5
	// hash
	rfc2869.MessageAuthenticator_Set(request.Packet, ZeroAuthenticator[0:16])
	encode, err := request.Packet.Encode()
	if err != nil {
		log.WithError(err).Error("Unable to encode zered radius request")
		return err
	}

	// Protect log statement as it invokes string formatting
	if log.GetLevel() >= log.DebugLevel {
		log.
			WithFields(log.Fields{
				"request": fmt.Sprintf("%02x", encode),
			}).
			Debug("RADIUS request used to generate hash")
	}

	// Generate the HMAC.MD5 hash and set it back into the packet
	hash := hmac.New(md5.New, []byte(app.SharedSecret))
	hash.Write(encode)
	rfc2869.MessageAuthenticator_Set(request.Packet, hash.Sum(nil))

	// Protect log statement as it invokes string formatting
	if log.GetLevel() >= log.DebugLevel {
		encode, _ = request.Packet.Encode()
		log.
			WithFields(log.Fields{
				"request": fmt.Sprintf("%02x", encode),
			}).
			Debug("Final RADIUS request")
	}

	// Queue request to the RADIUS server
	request.Supplicant.RadiusRequestQueue <- request
	return nil
}
