package wg

import (
	"strings"
	"testing"
)

const k1 = "YAnz7Zr6nZ1lQyGQKu4l1Kd3tQyQyYnzAqJbX6m7m0M="
const k2 = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="

func sample(allowed string) string {
	return "[Interface]\nPrivateKey = " + k1 + "\nAddress = 10.8.0.41/32\nDNS = 10.8.0.1\n\n[Peer]\nPublicKey = " + k2 +
		"\nPresharedKey = " + k1 + "\nEndpoint = gate.example.org:51820\nAllowedIPs = " + allowed + "\nPersistentKeepalive = 25\n"
}

func TestParseRoutesOnlyTheVPN(t *testing.T) {
	w, fb, err := Parse(sample("0.0.0.0/0"), "10.8.0.0/24", "h1")
	if err != nil || fb {
		t.Fatalf("%v %v", err, fb)
	}
	if w.AllowedIPs != "10.8.0.0/24" || w.Address != "10.8.0.41/32" || w.Endpoint != "gate.example.org:51820" || w.Hash != "h1" {
		t.Fatalf("%+v", w)
	}
	q := Quick(w)
	if strings.Contains(q, "DNS") || strings.Contains(q, "0.0.0.0/0") || !strings.Contains(q, "AllowedIPs = 10.8.0.0/24") {
		t.Fatalf("quick file:\n%s", q)
	}
}

func TestParseFallbackSubnet(t *testing.T) {
	w, fb, err := Parse(sample("0.0.0.0/0"), "", "")
	if err != nil || !fb || w.AllowedIPs != "10.8.0.0/24" {
		t.Fatalf("%+v %v %v", w, fb, err)
	}
}

func TestParseRejects(t *testing.T) {
	if _, _, err := Parse(strings.Replace(sample("10.8.0.0/24"), k2, "nope", 1), "10.8.0.0/24", ""); err == nil {
		t.Fatal("bad key accepted")
	}
	if _, _, err := Parse(sample("10.8.0.0/24"), "192.168.0.0/24", ""); err == nil {
		t.Fatal("subnet without the address accepted")
	}
	if _, _, err := Parse(strings.Replace(sample("x"), "gate.example.org:51820", "gate", 1), "", ""); err == nil {
		t.Fatal("bad endpoint accepted")
	}
}
