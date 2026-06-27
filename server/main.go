// Relay + control plane. The data plane stays a blind ciphertext fan-out keyed
// by terminal id; the control plane (accounts, tokens, terminal registry,
// presence) is what makes it a product instead of a shared session string.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// hello is the first (text) frame a client sends.
type hello struct {
	Type     string `json:"type"`     // "hello"
	Token    string `json:"token"`    // login token -> account
	Terminal string `json:"terminal"` // terminal id (the relay session); empty for role "control"
	Role     string `json:"role"`     // "host" | "viewer" | "control"
}

// presence is pushed to an account's control connections when a terminal's host
// comes or goes.
type presence struct {
	Type     string `json:"type"` // "presence"
	Terminal string `json:"terminal"`
	Online   bool   `json:"online"`
}

type server struct {
	store *Store
	hub   *hub
}

// ---- hub: sessions (data plane) + control conns (presence) ----

const scrollbackCap = 256 << 10 // 256 KiB of host-output ciphertext per session

type frame struct {
	binary bool
	data   []byte
}

type member struct {
	conn     *websocket.Conn
	role     string
	account  int64
	terminal string
	out      chan frame
}

type session struct {
	members    map[*member]struct{}
	hasHost    bool
	scrollback [][]byte
	backBytes  int
}

type hub struct {
	mu       sync.Mutex
	sessions map[string]*session
	controls map[int64]map[*member]struct{} // account -> control conns
}

func newHub() *hub {
	return &hub{sessions: map[string]*session{}, controls: map[int64]map[*member]struct{}{}}
}

func (h *hub) isOnline(terminal string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.sessions[terminal]
	return s != nil && s.hasHost
}

// joinSession adds m and returns scrollback to replay. ok is false if a host
// joins a session that already has one (would create an output->input loop).
func (h *hub) joinSession(name string, m *member) (replay [][]byte, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.sessions[name]
	if s == nil {
		s = &session{members: map[*member]struct{}{}}
		h.sessions[name] = s
	}
	if m.role == "host" {
		if s.hasHost {
			if len(s.members) == 0 {
				delete(h.sessions, name)
			}
			return nil, false
		}
		s.hasHost = true
		s.members[m] = struct{}{}
		return nil, true
	}
	s.members[m] = struct{}{}
	replay = make([][]byte, len(s.scrollback))
	copy(replay, s.scrollback)
	return replay, true
}

func (h *hub) leaveSession(name string, m *member) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s := h.sessions[name]; s != nil {
		delete(s.members, m)
		if m.role == "host" {
			s.hasHost = false
		}
		if len(s.members) == 0 {
			delete(h.sessions, name)
		}
	}
}

func (h *hub) broadcast(name string, sender *member, data []byte) {
	h.mu.Lock()
	s := h.sessions[name]
	if s == nil {
		h.mu.Unlock()
		return
	}
	if sender.role == "host" {
		f := append([]byte(nil), data...)
		s.scrollback = append(s.scrollback, f)
		s.backBytes += len(f)
		for s.backBytes > scrollbackCap && len(s.scrollback) > 1 {
			s.backBytes -= len(s.scrollback[0])
			s.scrollback = s.scrollback[1:]
		}
	}
	targets := make([]*member, 0, len(s.members))
	for m := range s.members {
		if m != sender {
			targets = append(targets, m)
		}
	}
	h.mu.Unlock()
	send(targets, frame{binary: true, data: data}, name)
}

func (h *hub) addControl(account int64, m *member) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.controls[account] == nil {
		h.controls[account] = map[*member]struct{}{}
	}
	h.controls[account][m] = struct{}{}
}

func (h *hub) removeControl(account int64, m *member) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if set := h.controls[account]; set != nil {
		delete(set, m)
		if len(set) == 0 {
			delete(h.controls, account)
		}
	}
}

// notifyPresence pushes a terminal's online/offline change to the owning
// account's control connections — the "ws通知" of the spec.
func (h *hub) notifyPresence(account int64, terminal string, online bool) {
	msg, _ := json.Marshal(presence{Type: "presence", Terminal: terminal, Online: online})
	h.mu.Lock()
	targets := make([]*member, 0, len(h.controls[account]))
	for m := range h.controls[account] {
		targets = append(targets, m)
	}
	h.mu.Unlock()
	send(targets, frame{binary: false, data: msg}, terminal)
}

func send(targets []*member, f frame, name string) {
	for _, m := range targets {
		select {
		case m.out <- f:
		default:
			log.Printf("session %s: dropping frame, slow consumer", name)
		}
	}
}

// ---- WS handler ----

func (sv *server) handleWS(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
	if err != nil {
		return
	}
	defer c.CloseNow()
	ctx := r.Context()
	c.SetReadLimit(16 << 20)

	typ, data, err := c.Read(ctx)
	if err != nil || typ != websocket.MessageText {
		c.Close(websocket.StatusUnsupportedData, "expected hello")
		return
	}
	var hi hello
	if err := json.Unmarshal(data, &hi); err != nil || hi.Type != "hello" {
		c.Close(websocket.StatusUnsupportedData, "bad hello")
		return
	}
	account := sv.store.accountByToken(hi.Token)
	if account == 0 {
		c.Close(websocket.StatusPolicyViolation, "unauthorized")
		return
	}

	m := &member{conn: c, role: hi.Role, account: account, terminal: hi.Terminal, out: make(chan frame, 256)}

	switch hi.Role {
	case "control":
		sv.hub.addControl(account, m)
		defer sv.hub.removeControl(account, m)
		log.Printf("account %d: control connected", account)
		sv.runPump(ctx, c, m, nil)
		return

	case "host", "viewer":
		if sv.store.terminalAccount(hi.Terminal) != account {
			c.Close(websocket.StatusPolicyViolation, "not your terminal")
			return
		}
		replay, ok := sv.hub.joinSession(hi.Terminal, m)
		if !ok {
			c.Close(websocket.StatusPolicyViolation, "terminal already has a host")
			return
		}
		defer sv.hub.leaveSession(hi.Terminal, m)
		log.Printf("terminal %s: %s joined (account %d)", hi.Terminal, hi.Role, account)
		if hi.Role == "host" {
			sv.hub.notifyPresence(account, hi.Terminal, true)
			defer sv.hub.notifyPresence(account, hi.Terminal, false)
		}
		sv.runPump(ctx, c, m, replay)
		return

	default:
		c.Close(websocket.StatusUnsupportedData, "bad role")
	}
}

// runPump replays any scrollback, then concurrently writes queued frames and
// relays inbound binary frames to the session. Returns when the conn closes.
func (sv *server) runPump(ctx context.Context, c *websocket.Conn, m *member, replay [][]byte) {
	for _, f := range replay {
		if err := c.Write(ctx, websocket.MessageBinary, f); err != nil {
			return
		}
	}
	writerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		// Ping keeps the connection alive through Cloudflare, which idle-closes a
		// proxied WebSocket after ~100s, and surfaces dead conns sooner.
		ping := time.NewTicker(30 * time.Second)
		defer ping.Stop()
		for {
			select {
			case <-writerCtx.Done():
				return
			case <-ping.C:
				pctx, pc := context.WithTimeout(writerCtx, 10*time.Second)
				err := c.Ping(pctx)
				pc()
				if err != nil {
					cancel()
					return
				}
			case f := <-m.out:
				mt := websocket.MessageBinary
				if !f.binary {
					mt = websocket.MessageText
				}
				if err := c.Write(writerCtx, mt, f.data); err != nil {
					cancel()
					return
				}
			}
		}
	}()
	for {
		typ, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		// Only data-plane roles relay; control conns just receive.
		if typ == websocket.MessageBinary && (m.role == "host" || m.role == "viewer") {
			sv.hub.broadcast(m.terminal, m, data)
		}
	}
}

func main() {
	addr := flag.String("addr", ":8799", "listen address")
	dbPath := flag.String("db", "newterminal.db", "sqlite path")
	flag.Parse()

	store, err := openStore(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	sv := &server{store: store, hub: newHub()}

	mux := http.NewServeMux()
	mux.HandleFunc("/register", sv.handleRegister)
	mux.HandleFunc("/login", sv.handleLogin)
	mux.HandleFunc("/terminals", sv.handleTerminals)
	mux.HandleFunc("/ws", sv.handleWS)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	log.Printf("relay listening on %s (db %s)", *addr, *dbPath)
	log.Fatal(http.ListenAndServe(*addr, cors(mux)))
}

// cors lets the desktop webview and mobile (different origins) call the HTTP API.
// ponytail: wide-open for self-use; restrict origins if this is ever exposed.
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
