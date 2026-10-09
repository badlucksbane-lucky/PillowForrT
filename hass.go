package main

// Home Assistant over MQTT. With a broker on the LAN the box announces itself through MQTT discovery (one device, "PillowForrT", with its sensors) and then
// publishes its state every 30 seconds and each event as it happens:
//
//   - sensors: uplink (connectivity), uplink latency, Wi-Fi clients, temperature, events needing attention, the last event's text, data used this cycle, DNS queries
//     and blocks (counters), encrypted DNS (off while the stub is on the carrier's fallback), VPN up, Tor ready.
//   - one device_tracker per device the presence watch knows (home / not_home, named by its label, host name or MAC), so automations can key on who is here.
//   - optionally one switch per device for its internet (off = paused for the configured minutes, on = resumed). That is a remote write, so it is off until you turn
//     "control" on, and it only ever pauses or resumes: nothing else on the page is reachable from the broker.
//   - <prefix>/<node>/event: each event as the same EVE record the stream serves, for MQTT-trigger automations.
//
// The broker must be on the LAN (plain MQTT 3.1.1, no TLS: export.go refuses any other address), and what is published names devices the way the page does, so
// it is for a broker you run, not a public one. Off until an address is given.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"strings"
	"sync"
	"time"
)

type hassPublisher struct {
	mu     sync.Mutex
	client *mqttClient
	kick   chan struct{}
	known  map[string]bool // devices announced this connection
	cfg    exportMQTT
}

var (
	hass          *hassPublisher
	errHassKicked = errors.New("settings changed")
)

func newHassPublisher() *hassPublisher {
	return &hassPublisher{kick: make(chan struct{}, 1), known: map[string]bool{}}
}

func (h *hassPublisher) reconnect() {
	select {
	case h.kick <- struct{}{}:
	default:
	}
}

func macSlug(mac string) string { return strings.ReplaceAll(strings.ToLower(mac), ":", "") }

// hassDevice is the device block every entity carries, so Home Assistant files them under one device.
func hassDevice(node string) map[string]any {
	return map[string]any{"identifiers": []string{"pillowforrt-" + node}, "name": "PillowForrT", "manufacturer": "PillowForrT", "model": "Orbic RC400L", "sw_version": version}
}

type hassEntity struct {
	Component string // sensor, binary_sensor, device_tracker, switch
	Object    string
	Config    map[string]any
}

// hassEntities lists the box's own entities; all read the one JSON state topic.
func hassEntities(prefix, node string) []hassEntity {
	base := prefix + "/" + node
	dev := hassDevice(node)
	mk := func(comp, obj, name string, extra map[string]any) hassEntity {
		c := map[string]any{"name": name, "unique_id": "stone_" + node + "_" + obj, "state_topic": base + "/state", "availability_topic": base + "/availability", "device": dev}
		for k, v := range extra {
			c[k] = v
		}
		return hassEntity{comp, obj, c}
	}
	return []hassEntity{
		mk("binary_sensor", "uplink", "Uplink", map[string]any{"device_class": "connectivity", "value_template": "{{ value_json.uplink }}", "payload_on": "on", "payload_off": "off"}),
		mk("sensor", "latency", "Uplink latency", map[string]any{"unit_of_measurement": "ms", "value_template": "{{ value_json.latency_ms }}", "state_class": "measurement", "icon": "mdi:timer-outline"}),
		mk("sensor", "wifi_clients", "Wi-Fi clients", map[string]any{"value_template": "{{ value_json.wifi_clients }}", "state_class": "measurement", "icon": "mdi:wifi"}),
		mk("sensor", "temperature", "Temperature", map[string]any{"unit_of_measurement": "°C", "device_class": "temperature", "value_template": "{{ value_json.temp_c }}", "state_class": "measurement"}),
		mk("sensor", "events_unseen", "Events needing attention", map[string]any{"value_template": "{{ value_json.events_unseen }}", "icon": "mdi:bell-alert-outline"}),
		mk("sensor", "last_event", "Last event", map[string]any{"value_template": "{{ value_json.last_event }}", "icon": "mdi:text-box-outline"}),
		mk("sensor", "data_used", "Data used this cycle", map[string]any{"unit_of_measurement": "GB", "device_class": "data_size", "value_template": "{{ value_json.data_used_gb }}", "state_class": "total_increasing"}),
		mk("sensor", "dns_queries", "DNS queries", map[string]any{"value_template": "{{ value_json.dns_queries }}", "state_class": "total_increasing", "icon": "mdi:dns"}),
		mk("sensor", "dns_blocked", "DNS blocked", map[string]any{"value_template": "{{ value_json.dns_blocked }}", "state_class": "total_increasing", "icon": "mdi:dns-outline"}),
		mk("binary_sensor", "dns_encrypted", "Encrypted DNS", map[string]any{"value_template": "{{ value_json.dns_encrypted }}", "payload_on": "on", "payload_off": "off", "icon": "mdi:lock"}),
		mk("binary_sensor", "vpn", "VPN", map[string]any{"device_class": "connectivity", "value_template": "{{ value_json.vpn }}", "payload_on": "on", "payload_off": "off"}),
		mk("sensor", "cell", "Serving cell", map[string]any{"value_template": "{{ value_json.cell }}", "icon": "mdi:radio-tower"}),
		mk("sensor", "cell_signal", "Cell signal", map[string]any{"unit_of_measurement": "dBm", "device_class": "signal_strength", "value_template": "{{ value_json.cell_dbm }}", "state_class": "measurement"}),
		mk("binary_sensor", "tor", "Tor", map[string]any{"device_class": "connectivity", "value_template": "{{ value_json.tor }}", "payload_on": "on", "payload_off": "off"}),
	}
}

func hassTrackerConfig(prefix, node, mac, name string) map[string]any {
	base := prefix + "/" + node + "/dev/" + macSlug(mac)
	return map[string]any{"name": name, "unique_id": "stone_" + node + "_dev_" + macSlug(mac), "state_topic": base + "/presence", "payload_home": "home", "payload_not_home": "not_home",
		"source_type": "router", "availability_topic": prefix + "/" + node + "/availability", "device": hassDevice(node)}
}

func hassSwitchConfig(prefix, node, mac, name string) map[string]any {
	base := prefix + "/" + node + "/dev/" + macSlug(mac)
	return map[string]any{"name": name + " internet", "unique_id": "stone_" + node + "_net_" + macSlug(mac), "state_topic": base + "/internet", "command_topic": base + "/internet/set",
		"payload_on": "on", "payload_off": "off", "icon": "mdi:web", "availability_topic": prefix + "/" + node + "/availability", "device": hassDevice(node)}
}

// hassState is the JSON the box's own entities read.
type hassState struct {
	Uplink       string  `json:"uplink"`
	LatencyMs    float64 `json:"latency_ms"`
	WifiClients  int     `json:"wifi_clients"`
	TempC        float64 `json:"temp_c"`
	EventsUnseen int     `json:"events_unseen"`
	LastEvent    string  `json:"last_event"`
	DataUsedGB   float64 `json:"data_used_gb"`
	DNSQueries   uint64  `json:"dns_queries"`
	DNSBlocked   uint64  `json:"dns_blocked"`
	DNSEncrypted string  `json:"dns_encrypted"`
	VPN          string  `json:"vpn"`
	Tor          string  `json:"tor"`
	Cell         string  `json:"cell"`     // "LTE 310-410 tac 12345 cell 67890123", or "" when the tower watch is off
	CellSignal   int     `json:"cell_dbm"` // RSRP when known, else RSSI
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func hassStateFrom(in metricsIn, lastEvent string) hassState {
	s := hassState{LastEvent: lastEvent, EventsUnseen: in.EventsUnseen, WifiClients: in.Wifi24Clients + in.Wifi5Clients}
	if in.Uplink != nil {
		s.Uplink = onOff(in.Uplink.OK)
		s.LatencyMs = math.Round(in.Uplink.LatencyMs*10) / 10
	}
	if in.Sys != nil {
		for _, t := range in.Sys.Temps {
			if t.C > s.TempC {
				s.TempC = t.C
			}
		}
	}
	if in.UsageSet {
		s.DataUsedGB = math.Round((in.UsageDown+in.UsageUp)/1e9*100) / 100
	}
	if in.DNS != nil {
		s.DNSQueries, s.DNSBlocked = in.DNS.Queries, in.DNS.Blocked
		s.DNSEncrypted = onOff(!in.DNS.Fallback)
	} else {
		s.DNSEncrypted = "off"
	}
	s.VPN = onOff(in.VPN != nil && in.VPN.Up)
	s.Tor = onOff(in.Tor != nil && in.Tor.Ready)
	if towers != nil {
		if c := towers.View().Current; c != nil {
			s.Cell = fmt.Sprintf("%s %d-%s tac %d cell %d", c.Tech, c.MCC, c.MNC, c.TAC, c.CI)
			s.CellSignal = c.RSSI
			if c.RSRP != 0 {
				s.CellSignal = int(c.RSRP)
			}
		}
	}
	return s
}

// deviceName: the label you gave, else what the device calls itself, else the MAC.
func deviceName(mac string) string {
	if devMgr != nil {
		if n := devMgr.All()[mac]; n.Label != "" {
			return n.Label
		}
	}
	if presence != nil {
		if n := presence.Who(mac); n != "" {
			return n
		}
	}
	return mac
}

// run keeps a connection to the broker while the export is on, publishing discovery on connect and state on a timer; it sleeps while off.
func (h *hassPublisher) run() {
	for {
		cfg := exports.Cfg().MQTT
		if !cfg.Enabled || cfg.Addr == "" {
			exports.setMQTTState("off")
			<-h.kick
			continue
		}
		exports.setMQTTState("connecting")
		err := h.session(cfg)
		h.mu.Lock()
		h.client = nil
		h.known = map[string]bool{}
		h.mu.Unlock()
		if err == errHassKicked {
			continue // settings changed: straight back with the new ones
		}
		if err != nil {
			exports.setMQTTState("error: " + err.Error())
			log.Printf("home assistant: %v", err)
		} else {
			exports.setMQTTState("off")
		}
		select {
		case <-h.kick:
		case <-time.After(30 * time.Second):
		}
	}
}

func (h *hassPublisher) session(cfg exportMQTT) error {
	node, prefix := orStr(cfg.NodeID, "box"), orStr(cfg.Prefix, "pillowforrt")
	base := prefix + "/" + node
	conn, err := exports.dial("tcp", cfg.Addr)
	if err != nil {
		return fmt.Errorf("could not reach the broker: %v", err)
	}
	cl, err := mqttDial(conn, mqttOpts{ClientID: "stone-" + node, User: cfg.User, Pass: cfg.Pass, WillTopic: base + "/availability", WillPayload: "offline"}, func(topic string, payload []byte) {
		h.command(cfg, topic, string(payload))
	})
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.client, h.cfg = cl, cfg
	h.known = map[string]bool{}
	h.mu.Unlock()
	exports.setMQTTState("connected")
	defer cl.Close()
	for _, e := range hassEntities(prefix, node) {
		b, _ := json.Marshal(e.Config)
		if err := cl.Publish("homeassistant/"+e.Component+"/stone_"+node+"/"+e.Object+"/config", b, true); err != nil {
			return err
		}
	}
	if cfg.Control {
		if err := cl.Subscribe(base + "/dev/+/internet/set"); err != nil {
			return err
		}
	}
	if err := cl.Publish(base+"/availability", []byte("online"), true); err != nil {
		return err
	}
	if err := h.publishState(cl, cfg); err != nil {
		return err
	}
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	ping := time.NewTicker(mqttKeepAliveS / 2 * time.Second)
	defer ping.Stop()
	for {
		select {
		case err := <-cl.Err():
			return fmt.Errorf("the broker connection dropped: %v", err)
		case <-h.kick:
			return errHassKicked
		case <-ping.C:
			if err := cl.Ping(); err != nil {
				return err
			}
		case <-tick.C:
			if err := h.publishState(cl, cfg); err != nil {
				return err
			}
		}
	}
}

func (h *hassPublisher) lastEventText() string {
	if events == nil {
		return ""
	}
	v := events.View()
	if len(v.Events) == 0 {
		return ""
	}
	return v.Events[0].Text
}

func (h *hassPublisher) publishState(cl *mqttClient, cfg exportMQTT) error {
	node, prefix := orStr(cfg.NodeID, "box"), orStr(cfg.Prefix, "pillowforrt")
	base := prefix + "/" + node
	st := hassStateFrom(gatherMetrics(), h.lastEventText())
	b, _ := json.Marshal(st)
	if err := cl.Publish(base+"/state", b, true); err != nil {
		return err
	}
	if presence == nil {
		return nil
	}
	cut := map[string]bool{}
	if fwMgr != nil {
		for _, m := range fwMgr.View(map[string]string{}).CutNow {
			cut[strings.ToLower(m)] = true
		}
	}
	for mac, info := range presence.Info() {
		slug := macSlug(mac)
		h.mu.Lock()
		announced := h.known[mac]
		h.known[mac] = true
		h.mu.Unlock()
		if !announced {
			name := deviceName(mac)
			tb, _ := json.Marshal(hassTrackerConfig(prefix, node, mac, name))
			if err := cl.Publish("homeassistant/device_tracker/stone_"+node+"_"+slug+"/config", tb, true); err != nil {
				return err
			}
			if cfg.Control {
				sb, _ := json.Marshal(hassSwitchConfig(prefix, node, mac, name))
				if err := cl.Publish("homeassistant/switch/stone_"+node+"_"+slug+"/config", sb, true); err != nil {
					return err
				}
			}
		}
		pres := "not_home"
		if info.Online {
			pres = "home"
		}
		if err := cl.Publish(base+"/dev/"+slug+"/presence", []byte(pres), true); err != nil {
			return err
		}
		if cfg.Control {
			if err := cl.Publish(base+"/dev/"+slug+"/internet", []byte(onOff(!cut[mac])), true); err != nil {
				return err
			}
		}
	}
	return nil
}

// command handles a switch write from Home Assistant: <prefix>/<node>/dev/<mac>/internet/set with "on" or "off".
func (h *hassPublisher) command(cfg exportMQTT, topic, payload string) {
	if !cfg.Control || fwMgr == nil {
		return
	}
	mac, ok := parseInternetCommand(orStr(cfg.Prefix, "pillowforrt"), orStr(cfg.NodeID, "box"), topic)
	if !ok {
		return
	}
	var err error
	switch strings.ToLower(strings.TrimSpace(payload)) {
	case "off":
		err = fwMgr.Pause(mac, cfg.PauseMinutes)
	case "on":
		err = fwMgr.Resume(mac)
	default:
		return
	}
	if err != nil {
		log.Printf("home assistant command for %s: %v", mac, err)
		return
	}
	h.mu.Lock()
	cl := h.client
	h.mu.Unlock()
	if cl != nil {
		h.publishState(cl, cfg)
	}
}

// parseInternetCommand turns the command topic back into a MAC; a slug that is not twelve hex digits is refused.
func parseInternetCommand(prefix, node, topic string) (string, bool) {
	pre := prefix + "/" + node + "/dev/"
	if !strings.HasPrefix(topic, pre) || !strings.HasSuffix(topic, "/internet/set") {
		return "", false
	}
	slug := strings.TrimSuffix(strings.TrimPrefix(topic, pre), "/internet/set")
	if len(slug) != 12 {
		return "", false
	}
	var parts []string
	for i := 0; i < 12; i += 2 {
		for _, c := range slug[i : i+2] {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return "", false
			}
		}
		parts = append(parts, slug[i:i+2])
	}
	return strings.Join(parts, ":"), true
}

// event publishes one event to the event topic, when connected.
func (h *hassPublisher) event(e evt) {
	h.mu.Lock()
	cl, cfg := h.client, h.cfg
	h.mu.Unlock()
	if cl == nil {
		return
	}
	b, _ := json.Marshal(toEVE(e, *uiHost, false))
	cl.Publish(orStr(cfg.Prefix, "pillowforrt")+"/"+orStr(cfg.NodeID, "box")+"/event", b, false)
}
