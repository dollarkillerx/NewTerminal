package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func mem(role string) *member { return &member{role: role, out: make(chan frame, 8)} }

// broadcast must reach every other member of a session but never the sender.
func TestBroadcastFanOutExcludesSender(t *testing.T) {
	h := newHub()
	sender, a, b := mem("host"), mem("viewer"), mem("viewer")
	h.joinSession("s1", sender)
	h.joinSession("s1", a)
	h.joinSession("s1", b)
	h.joinSession("other", mem("viewer"))

	msg := []byte("hello")
	h.broadcast("s1", sender, msg)

	for name, m := range map[string]*member{"a": a, "b": b} {
		select {
		case got := <-m.out:
			if !got.binary || !bytes.Equal(got.data, msg) {
				t.Fatalf("%s got %v, want binary %q", name, got, msg)
			}
		default:
			t.Fatalf("%s received nothing", name)
		}
	}
	if len(sender.out) != 0 {
		t.Fatal("sender received its own frame")
	}
}

func TestLeaveCleansUpEmptyRoom(t *testing.T) {
	h := newHub()
	m := mem("viewer")
	h.joinSession("s1", m)
	h.leaveSession("s1", m)
	if _, ok := h.sessions["s1"]; ok {
		t.Fatal("empty room not cleaned up")
	}
}

// A late-joining viewer must replay host output, but never viewer input.
func TestScrollbackReplaysHostOutputOnly(t *testing.T) {
	h := newHub()
	host, viewer1 := mem("host"), mem("viewer")
	h.joinSession("s1", host)
	h.joinSession("s1", viewer1)
	h.broadcast("s1", host, []byte("OUT"))     // buffered
	h.broadcast("s1", viewer1, []byte("KEYS")) // not buffered

	replay, ok := h.joinSession("s1", mem("viewer"))
	if !ok || len(replay) != 1 || !bytes.Equal(replay[0], []byte("OUT")) {
		t.Fatalf("scrollback = %q ok=%v, want [OUT] true", replay, ok)
	}
}

// A second host in a session must be rejected to avoid an output->input loop.
func TestSecondHostRejected(t *testing.T) {
	h := newHub()
	if _, ok := h.joinSession("s1", mem("host")); !ok {
		t.Fatal("first host should be accepted")
	}
	if _, ok := h.joinSession("s1", mem("host")); ok {
		t.Fatal("second host should be rejected")
	}
	if _, ok := h.joinSession("s1", mem("viewer")); !ok {
		t.Fatal("viewer should be accepted alongside a host")
	}
}

// After a host's connection closes, a fresh host must be able to rejoin — this
// is what makes desktop auto-reconnect work.
func TestHostCanRejoinAfterLeave(t *testing.T) {
	h := newHub()
	h1 := mem("host")
	if _, ok := h.joinSession("s1", h1); !ok {
		t.Fatal("first host rejected")
	}
	h.leaveSession("s1", h1) // connection dropped
	if _, ok := h.joinSession("s1", mem("host")); !ok {
		t.Fatal("host could not rejoin after the previous one left")
	}
}

func TestScrollbackEvictsOldest(t *testing.T) {
	h := newHub()
	host := mem("host")
	h.joinSession("s1", host)
	big := bytes.Repeat([]byte("x"), 100<<10) // 100 KiB each; cap is 256 KiB
	for range 5 {
		h.broadcast("s1", host, big)
	}
	if s := h.sessions["s1"]; s.backBytes > scrollbackCap {
		t.Fatalf("backBytes %d exceeds cap %d", s.backBytes, scrollbackCap)
	}
}

// Presence pushes a JSON notice to the account's control connections.
func TestPresenceNotifiesControls(t *testing.T) {
	h := newHub()
	ctrl := &member{role: "control", account: 7, out: make(chan frame, 4)}
	h.addControl(7, ctrl)
	h.notifyPresence(7, "term-abc", true)

	select {
	case f := <-ctrl.out:
		if f.binary {
			t.Fatal("presence should be a text frame")
		}
		var p presence
		if err := json.Unmarshal(f.data, &p); err != nil || p.Terminal != "term-abc" || !p.Online {
			t.Fatalf("bad presence %s (%v)", f.data, err)
		}
	default:
		t.Fatal("control received no presence")
	}
	// Other accounts must not be notified.
	other := &member{role: "control", account: 9, out: make(chan frame, 4)}
	h.addControl(9, other)
	h.notifyPresence(7, "term-abc", false)
	if len(other.out) != 0 {
		t.Fatal("presence leaked to another account")
	}
}

// argon2id hashing must verify the right password and reject the wrong one.
func TestPasswordHashRoundTrip(t *testing.T) {
	h := hashPassword("correct horse")
	if !verifyPassword("correct horse", h) {
		t.Fatal("correct password rejected")
	}
	if verifyPassword("wrong", h) {
		t.Fatal("wrong password accepted")
	}
}
