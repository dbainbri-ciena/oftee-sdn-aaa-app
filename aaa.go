// Exmaple AAA SDN application, that responds to 802.1x authentication packets,
// EAPOL, and proxies the request to a RADIUS server for processing.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/gorilla/mux"
	"github.com/kelseyhightower/envconfig"
	of "github.com/netrack/openflow"
	"github.com/netrack/openflow/ofp"
	log "github.com/sirupsen/logrus"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

type OpenFlowContext struct {
	DatapathID uint64
	Port       uint32
}

func (c *OpenFlowContext) String() string {
	return fmt.Sprintf("[0x%016x, 0x%04x]", c.DatapathID, c.Port)
}

func (c *OpenFlowContext) Len() uint64 {
	return 12
}

func (c *OpenFlowContext) ReadFrom(r io.Reader) (int, error) {
	buf := make([]byte, 12)
	n, err := r.Read(buf)
	if err != nil {
		return n, err
	}
	c.DatapathID = binary.BigEndian.Uint64(buf)
	c.Port = binary.BigEndian.Uint32(buf[8:])
	return n, err
}

type OpenFlowPacketInMessage struct {
	Context  OpenFlowContext
	Header   of.Header
	PacketIn ofp.PacketIn
}

type App struct {
	ShowHelp bool   `envconfig:"HELP" default:"false" desc:"show this message"`
	LogLevel string `envconfig:"LOG_LEVEL" default:"debug" desc:"logging level"`

	OfTeeApi string `envconfig:"OFTEE_API" default:"http://127.0.0.1:8002" desc:"HOST:PORT on which to connect to OFTEE REST API"`
	ListenOn string `envconfig:"LISTEN_ON" default:"127.0.0.1:8005" desc:"HOST:PORT on which to listen for packets from oftee"`
	RadiusAt string `envconfig:"RADIUS_AT" default:"127.0.0.1:1812" desc:"HOST:PORT of radius server to use"`

	queue chan *OpenFlowPacketInMessage
}

var idPool = make(map[uint8]bool)

func getId() uint8 {
	for i, v := range idPool {
		if !v {
			idPool[i] = true
			return i
		}
	}
	return 0
}

func clearId(id uint8) {
	idPool[id] = false
}

const (
	EAP_START             = 1 << 0
	EAP_REQUEST_IDENTITY  = 1 << 1
	EAP_RESPONSE_IDENTITY = 1 << 2
)

type Supplicant struct {
	Id uint8
}

var supplicants = make(map[string]*Supplicant)

func (app *App) emit(dpid uint64, portNo ofp.PortNo, data []byte) {
	packet := &bytes.Buffer{}
	pktOut := ofp.PacketOut{
		Buffer:  ofp.NoBuffer,
		InPort:  ofp.PortAny,
		Actions: ofp.Actions{&ofp.ActionOutput{portNo, ofp.ContentLenNoBuffer}},
	}
	req := of.NewRequest(of.TypePacketOut, packet)

	log.
		WithFields(log.Fields{
			"data": fmt.Sprintf("%02x", data),
			"len":  len(data),
		}).
		Debug("PACKET TO SEND")

	pktOut.WriteTo(packet)
	packet.Write(data)

	message := &bytes.Buffer{}
	req.WriteTo(message)

	log.
		WithFields(log.Fields{
			"data": fmt.Sprintf("%02x", message.Bytes()),
			"len":  len(message.Bytes()),
			"l2":   message.Len(),
			"l3":   packet.Len(),
		}).
		Debug("PACKET TO SEND2")
	url := fmt.Sprintf("%s/oftee/0x%016x", app.OfTeeApi, dpid)
	log.
		WithFields(log.Fields{
			"url": url,
		}).
		Debug("POSTING")
	resp, err := http.Post(url, "application/octet-stream", message)
	if err != nil {
		log.
			WithFields(log.Fields{
				"oftee": app.OfTeeApi,
			}).
			WithError(err).
			Fatal("Unable to connect to oftee API end point")
	} else if int(resp.StatusCode/100) != 2 {
		log.
			WithFields(log.Fields{
				"oftee":         app.OfTeeApi,
				"response-code": resp.StatusCode,
				"response":      resp.Status,
			}).
			Fatal("Non success code returned from oftee")
	}
}

func (app *App) PacketProcessor() {
	var message *OpenFlowPacketInMessage
	for {
		message = <-app.queue
		log.
			WithFields(log.Fields{
				"context":   message.Context.String(),
				"header":    message.Header,
				"packet_in": message.PacketIn,
			}).
			Debug("PROCESS")

		packet := gopacket.NewPacket(message.PacketIn.Data, layers.LayerTypeEthernet, gopacket.Default)
		log.
			WithFields(log.Fields{
				"packet": packet,
				"data":   fmt.Sprintf("%0x2", message.PacketIn.Data),
			}).
			Debug("packet")
		eapol := packet.Layer(layers.LayerTypeEAPOL)
		if eapol == nil {
			names := make([]string, len(packet.Layers()))
			for i, layer := range packet.Layers() {
				names[i] = layer.LayerType().String()
			}
			log.
				WithFields(log.Fields{
					"layers": names,
				}).
				Error("WRONG PACKET TYPE")
			continue
		}

		eth := layers.Ethernet{}
		eapol = packet.Layer(layers.LayerTypeEAPOL)
		e := layers.EAPOL{}
		eth.DecodeFromBytes(packet.LinkLayer().LayerContents(), nil)
		e.DecodeFromBytes(eapol.LayerContents(), nil)

		switch e.Type {
		case layers.EAPOLTypeStart:
			// If we have a start then if a record is not yet
			// created for this client, then create one and then
			// packet out to them a request for identity
			sup, ok := supplicants[eth.SrcMAC.String()]
			if !ok {
				log.
					WithFields(log.Fields{
						"supplicant": eth.SrcMAC.String(),
					}).
					Debug("START: Creating supplicant record")
				sup = &Supplicant{Id: getId()}
				supplicants[eth.SrcMAC.String()] = sup
			} else {
				log.
					WithFields(log.Fields{
						"supplicant": eth.SrcMAC.String(),
					}).
					Debug("START: Found supplicant record")
				sup = &Supplicant{}
			}

			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{}
			//gopacket.SerializeLayers(buf, opts,
			//	&layers.Ethernet{},
			//	&layers.IPv4{},
			//	&layers.TCP{},
			//	gopacket.Payload([]byte{1, 2, 3, 4}))
			//packetData := buf.Bytes()
			//app.emit(message.Context.DatapathID, ofp.PortNo(message.Context.Port), packetData)

			//buf = gopacket.NewSerializeBuffer()
			//opts = gopacket.SerializeOptions{}
			gopacket.SerializeLayers(buf, opts,
				&layers.Ethernet{
					SrcMAC: net.HardwareAddr{0xc0, 0xff, 0xee, 0xc0, 0xff, 0xee},
					DstMAC: net.HardwareAddr{0x01, 0x80, 0xC2, 0x00, 0x00, 0x03},
					// DstMAC:       eth.SrcMAC,
					EthernetType: layers.EthernetTypeEAPOL,
					Length:       0,
				},
				&layers.EAPOL{
					Version: e.Version,
					Type:    layers.EAPOLTypeEAP,
					Length:  5,
				},
				&layers.EAP{
					Id:       1,
					Type:     1, //layers.EAPTypeIdentity,
					Code:     layers.EAPCodeRequest,
					Length:   5,
					TypeData: []byte{0},
				})
			// &gopacket.Payload{uint8(layers.EAPTypeIdentity)})
			log.Debugf("LEN: %d %02x", len(buf.Bytes()), buf.Bytes())
			app.emit(message.Context.DatapathID, ofp.PortNo(message.Context.Port), buf.Bytes())
		case layers.EAPOLTypeEAP:
			sup, _ := supplicants[eth.SrcMAC.String()]
			log.Debug(sup)
			eap := &layers.EAP{}
			eap.DecodeFromBytes(packet.Layer(layers.LayerTypeEAP).LayerContents(), nil)
			switch eap.Type {
			case layers.EAPTypeNACK:
				log.Debug("NAK")
			case layers.EAPTypeIdentity:
				log.Debug("IDENTITY")
				log.Debug(string(eap.TypeData))
			}
			rad := radius.New(radius.CodeAccessRequest, []byte(`SECRET`))
			rfc2865.UserName_SetString(rad, string(eap.TypeData))
			rfc2865.NASIdentifier_Get(rad)
			//rfc.UserPassword_SetString(rad, "mypassword")
			ctx := context.Background()
			log.
				WithFields(log.Fields{
					"radius": app.RadiusAt,
				}).
				Debug("SENDING TO RAD")
			response, _ := radius.Exchange(ctx, rad, app.RadiusAt)

			log.Debugf("%+v", response)
		case layers.EAPOLTypeLogOff:
		default:
			log.Debug(e.Type.String())
		}
	}
}

func (app *App) EapPacketHandler(resp http.ResponseWriter, req *http.Request) {

	defer req.Body.Close()
	data, err := ioutil.ReadAll(req.Body)
	log.Debugf("HERE %d", len(data))
	log.
		WithFields(log.Fields{
			"packet": fmt.Sprintf("%d %02x", len(data), data),
		}).
		Debug("received packet")
	if err != nil {
		http.Error(resp, "Unable to read packet", http.StatusInternalServerError)
		return
	}

	var context OpenFlowContext
	var header of.Header
	var packetIn ofp.PacketIn
	reader := bytes.NewReader(data)
	_, err = context.ReadFrom(reader)
	if err != nil {
		log.WithError(err).Fatal("oh well")
		http.Error(resp, "Unable to parse open flow message context", http.StatusInternalServerError)
		return
	}

	_, err = header.ReadFrom(reader)
	if err != nil {
		http.Error(resp, "Unable to parse open flow message header", http.StatusInternalServerError)
		return
	}
	_, err = packetIn.ReadFrom(reader)
	if err != nil {
		http.Error(resp, "Unable to parse packet in message", http.StatusInternalServerError)
		return
	}

	log.
		WithFields(log.Fields{
			"context": context.String(),
			"openflow": fmt.Sprintf("%02x", data[context.Len():context.Len()+uint64(header.Length)]),
			"packet": fmt.Sprintf("%02x", packetIn.Data),
		}).
		Debug("BREAKDOWN")

	app.queue <- &OpenFlowPacketInMessage{
		Context:  context,
		Header:   header,
		PacketIn: packetIn,
	}
}

func main() {
	app := App{
		queue: make(chan *OpenFlowPacketInMessage),
	}

	var flags flag.FlagSet
	err := flags.Parse(os.Args[1:])
	if err != nil {
		envconfig.Usage("", &(app))
		return
	}

	err = envconfig.Process("", &app)
	if err != nil {
		log.
			WithError(err).
			Fatal("Unable to process configuration")
	}

	// Set the logging level, if it can't be parsed then default to warning
	logLevel, err := log.ParseLevel(app.LogLevel)
	if err != nil {
		log.
			WithFields(log.Fields{
				"log-level": app.LogLevel,
			}).
			WithError(err).
			Warn("Unable to parse log level specified, defaulting to Warning")
		logLevel = log.WarnLevel
	}
	log.SetLevel(logLevel)

	if app.ShowHelp {
		envconfig.Usage("", &app)
		return
	}

	router := mux.NewRouter()
	router.
		HandleFunc("/aaa/eap", app.EapPacketHandler).
		Headers("Content-type", "application/octet-stream").
		Methods("POST")

	http.Handle("/", router)
	log.Debug(app.ListenOn)
	server := &http.Server{
		Addr: app.ListenOn,
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	// Start packet processor
	go app.PacketProcessor()
	log.Fatal(server.ListenAndServe())
}
