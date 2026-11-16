package config

import (
	"os"
	"testing"
)

func testStore(t *testing.T) Store {
	d := t.TempDir()
	return Store{P: Paths{Etc: d, State: d, Run: d}}
}

func TestRoundTripAndModes(t *testing.T) {
	s := testStore(t)
	if _, err := s.LoadToken(); err != ErrNotEnrolled {
		t.Fatalf("want not enrolled, got %v", err)
	}
	if err := s.SaveToken("secret-token"); err != nil {
		t.Fatal(err)
	}
	tok, err := s.LoadToken()
	if err != nil || tok != "secret-token" {
		t.Fatalf("token %q %v", tok, err)
	}
	fi, _ := os.Stat(s.P.TokenFile())
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("token mode %v", fi.Mode().Perm())
	}
	a := &Agent{Server: "https://gate.example.org", Name: "pi"}
	a.Defaults()
	if err := s.SaveAgent(a); err != nil {
		t.Fatal(err)
	}
	fi, _ = os.Stat(s.P.AgentFile())
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("agent mode %v", fi.Mode().Perm())
	}
	b, err := s.LoadAgent()
	if err != nil || b.Interface != "wg-gc" || b.Confirm != ConfirmAsk || b.SSH.Port != 22 {
		t.Fatalf("agent %+v %v", b, err)
	}
	if err := s.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadAgent(); err != ErrNotEnrolled {
		t.Fatalf("after remove: %v", err)
	}
}

func TestNormalizeServer(t *testing.T) {
	ok := map[string]string{"gate.example.org": "https://gate.example.org", "https://gate.example.org/": "https://gate.example.org", "https://g.example:8443": "https://g.example:8443"}
	for in, want := range ok {
		got, err := NormalizeServer(in)
		if err != nil || got != want {
			t.Errorf("%q → %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"http://gate.example.org", "https://u:p@gate.example.org", "https://g.example/x", "https://g.example?a=1", ""} {
		if _, err := NormalizeServer(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestValidate(t *testing.T) {
	a := &Agent{Server: "https://g.example", Interface: "wg gc"}
	a.Defaults()
	if a.Validate() == nil {
		t.Fatal("bad interface accepted")
	}
	a.Interface = "wg-gc"
	a.Confirm = "never"
	if a.Validate() == nil {
		t.Fatal("bad confirm accepted")
	}
}
