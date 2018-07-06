// Exmaple AAA SDN application, that responds to 802.1x authentication packets,
// EAPOL, and proxies the request to a RADIUS server for processing.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/kelseyhightower/envconfig"
	"github.com/netrack/openflow"
	"github.com/netrack/openflow/ofp"
	log "github.com/sirupsen/logrus"
	"layeh.com/radius"
)

type App struct {
	ShowHelp bool   `envconfig:"HELP" default:"false" desc:"show this message"`
	LogLevel string `envconfig:"LOG_LEVEL" default:"debug" desc:"logging level"`

	OfTeeApi string `envconfig:"OFTEE_API" default:"http://127.0.0.1:8002" desc:"HOST:PORT on which to connect to OFTEE REST API"`
	ListenOn string `envconfig:"LISTEN_ON" default:"127.0.0.1:8005" desc:"HOST:PORT on which to listen for packets from oftee"`
	RadiusAt string `envconfig:"RADIUS_AT" default:"127.0.0.1:1812" desc:"HOST:PORT of radius server to use"`

	SharedSecret  string        `envconfig:"SHARED_SECRET" required:"true" desc:"shared secret to use when communicating to radius"`
	RadiusTimeout time.Duration `envconfig:"RADIUS_TIMEOUT" default:"15s" desc:"time out direction for RADIUS requests"`

	radiusPacketId      byte
	eapPacketId         byte
	radiusResponseQueue chan *AugmentedRadiusPacket
	packetInQueue       chan *OpenFlowPacketInMessage
	supplicants         map[string]*Supplicant
}

var ZeroAuthenticator = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

type AugmentedRadiusPacket struct {
	EAPOLVersion uint8
	Supplicant   *Supplicant
	Context      OpenFlowContext
	Packet       *radius.Packet
}

type OpenFlowPacketInMessage struct {
	Context  OpenFlowContext
	Header   openflow.Header
	PacketIn ofp.PacketIn
}

var idPool = make(map[uint8]bool)

func getId() uint8 {
	for i, v := range idPool {
		if !v {
			idPool[i] = true
			return i + 1
		}
	}
	return 0
}

func clearId(id uint8) {
	idPool[id] = false
}

// Receiver for OpenFlow PacketIns from OFTEE
func (app *App) EapPacketHandler(resp http.ResponseWriter, req *http.Request) {

	// Read and parse the packet form the HTTP Body
	defer req.Body.Close()
	data, err := ioutil.ReadAll(req.Body)
	log.
		WithFields(log.Fields{
			"packet": fmt.Sprintf("%d %02x", len(data), data),
		}).
		Debug("received packet")
	if err != nil {
		http.Error(resp, "Unable to read packet", http.StatusInternalServerError)
		return
	}

	// Parse the data into the various components: context, header, packet
	var context OpenFlowContext
	var header openflow.Header
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
			"context":  context.String(),
			"openflow": fmt.Sprintf("%02x", data[context.Len():context.Len()+uint64(header.Length)]),
			"packet":   fmt.Sprintf("%02x", packetIn.Data),
		}).
		Debug("BREAKDOWN")

	// Queue packet for processing
	app.packetInQueue <- &OpenFlowPacketInMessage{
		Context:  context,
		Header:   header,
		PacketIn: packetIn,
	}
}

func main() {
	app := App{
		packetInQueue:       make(chan *OpenFlowPacketInMessage),
		supplicants:         make(map[string]*Supplicant),
		radiusResponseQueue: make(chan *AugmentedRadiusPacket),
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
	go app.RadiusResponseProcessor()
	go app.SupplicantPacketProcessor()
	log.Fatal(server.ListenAndServe())
}
