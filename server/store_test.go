package main

import "testing"

func TestStoreAccountTokenTerminalFlow(t *testing.T) {
	s, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}

	id, err := s.createAccount("a@x.com", hashPassword("pw123456"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.createAccount("a@x.com", "h"); err != errTaken {
		t.Fatalf("duplicate email: got %v, want errTaken", err)
	}

	token, err := s.createToken(id)
	if err != nil {
		t.Fatal(err)
	}
	if s.accountByToken(token) != id {
		t.Fatal("token did not resolve to account")
	}
	if s.accountByToken("bogus") != 0 {
		t.Fatal("bogus token resolved to an account")
	}

	term, err := s.createTerminal(id, "macbook")
	if err != nil {
		t.Fatal(err)
	}
	if s.terminalAccount(term) != id {
		t.Fatal("terminal ownership wrong")
	}
	// A different account must not own this terminal (the WS access check).
	other, _ := s.createAccount("b@x.com", hashPassword("pw123456"))
	if s.terminalAccount(term) == other {
		t.Fatal("terminal leaked to another account")
	}

	terms, err := s.terminalsByAccount(id)
	if err != nil || len(terms) != 1 || terms[0].Name != "macbook" {
		t.Fatalf("list = %v (%v)", terms, err)
	}
}
