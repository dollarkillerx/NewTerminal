package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters. ponytail: fixed sensible defaults; expose as config only
// if you ever need to tune for a constrained host.
const (
	argTime    = 1
	argMemory  = 64 * 1024
	argThreads = 4
	argKeyLen  = 32
	argSaltLen = 16
)

func hashPassword(pw string) string {
	salt := make([]byte, argSaltLen)
	rand.Read(salt)
	h := argon2.IDKey([]byte(pw), salt, argTime, argMemory, argThreads, argKeyLen)
	enc := base64.RawStdEncoding.EncodeToString
	return "argon2id$" + enc(salt) + "$" + enc(h)
}

func verifyPassword(pw, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 3 || parts[0] != "argon2id" {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[1])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, argTime, argMemory, argThreads, argKeyLen)
	return subtle.ConstantTimeCompare(got, want) == 1
}

type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (sv *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil || c.Email == "" || len(c.Password) < 6 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and password (>=6 chars) required"})
		return
	}
	id, err := sv.store.createAccount(c.Email, hashPassword(c.Password))
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	token, err := sv.store.createToken(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (sv *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	id, hash, err := sv.store.accountByEmail(c.Email)
	if err != nil || !verifyPassword(c.Password, hash) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	token, err := sv.store.createToken(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

// authAccount extracts the bearer token and returns the account id, or 0.
func (sv *server) authAccount(r *http.Request) int64 {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return sv.store.accountByToken(token)
}

// handleTerminals: POST registers a new terminal (desktop), GET lists this
// account's terminals with live online status.
func (sv *server) handleTerminals(w http.ResponseWriter, r *http.Request) {
	account := sv.authAccount(r)
	if account == 0 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	switch r.Method {
	case http.MethodPost:
		var body struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Name == "" {
			body.Name = "terminal"
		}
		id, err := sv.store.createTerminal(account, body.Name)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"id": id, "name": body.Name})
	case http.MethodGet:
		terms, err := sv.store.terminalsByAccount(account)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "list"})
			return
		}
		for i := range terms {
			terms[i].Online = sv.hub.isOnline(terms[i].ID)
		}
		writeJSON(w, http.StatusOK, terms)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
