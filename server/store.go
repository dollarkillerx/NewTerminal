package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the whole persistence layer: accounts, login tokens and the terminals
// each account has registered. ponytail: one SQLite file, plain queries — no ORM,
// no migrations framework. Add those when the schema actually churns.
type Store struct{ db *sql.DB }

type Terminal struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Online bool   `json:"online"`
}

var errTaken = errors.New("email already registered")

func openStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	const schema = `
CREATE TABLE IF NOT EXISTS accounts (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  email     TEXT UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL,
  created   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
  token      TEXT PRIMARY KEY,
  account_id INTEGER NOT NULL,
  created    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS terminals (
  id         TEXT PRIMARY KEY,
  account_id INTEGER NOT NULL,
  name       TEXT NOT NULL,
  created    INTEGER NOT NULL
);`
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	return &Store{db}, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Store) createAccount(email, passHash string) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO accounts (email, pass_hash, created) VALUES (?, ?, ?)`,
		email, passHash, time.Now().Unix())
	if err != nil {
		// modernc surfaces the UNIQUE violation in the error text.
		return 0, errTaken
	}
	return res.LastInsertId()
}

func (s *Store) accountByEmail(email string) (id int64, passHash string, err error) {
	err = s.db.QueryRow(`SELECT id, pass_hash FROM accounts WHERE email = ?`, email).
		Scan(&id, &passHash)
	return
}

func (s *Store) createToken(accountID int64) (string, error) {
	token := randHex(32)
	_, err := s.db.Exec(`INSERT INTO tokens (token, account_id, created) VALUES (?, ?, ?)`,
		token, accountID, time.Now().Unix())
	return token, err
}

// accountByToken returns the account id for a valid token, or 0 if unknown.
func (s *Store) accountByToken(token string) int64 {
	var id int64
	if token == "" {
		return 0
	}
	_ = s.db.QueryRow(`SELECT account_id FROM tokens WHERE token = ?`, token).Scan(&id)
	return id
}

func (s *Store) createTerminal(accountID int64, name string) (string, error) {
	id := randHex(16)
	_, err := s.db.Exec(`INSERT INTO terminals (id, account_id, name, created) VALUES (?, ?, ?, ?)`,
		id, accountID, name, time.Now().Unix())
	return id, err
}

func (s *Store) terminalsByAccount(accountID int64) ([]Terminal, error) {
	rows, err := s.db.Query(`SELECT id, name FROM terminals WHERE account_id = ? ORDER BY created`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Terminal
	for rows.Next() {
		var t Terminal
		if err := rows.Scan(&t.ID, &t.Name); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// terminalAccount returns the owning account id for a terminal, or 0 if unknown.
func (s *Store) terminalAccount(terminalID string) int64 {
	var id int64
	_ = s.db.QueryRow(`SELECT account_id FROM terminals WHERE id = ?`, terminalID).Scan(&id)
	return id
}
