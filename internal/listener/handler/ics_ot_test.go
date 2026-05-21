package handler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

func TestATGInventory(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: time.Second}
	resC := make(chan Result, 1)
	go func() {
		r, _ := (&atg{id: identity.New("s")}).Handle(context.Background(), server, cfg)
		resC <- r
	}()
	_, _ = client.Write([]byte("\x01I20100"))
	buf := make([]byte, 4096)
	n, _ := client.Read(buf)
	_ = client.Close()
	r := <-resC
	out := string(buf[:n])
	if !strings.Contains(out, "IN-TANK INVENTORY") || !strings.Contains(out, "UNLEADED") {
		t.Errorf("atg report missing expected content: %q", out)
	}
	if r.Meta["atg_command"] != "I20100" {
		t.Errorf("atg_command = %v; want I20100", r.Meta["atg_command"])
	}
}

func TestFoxHello(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: time.Second}
	go func() { _, _ = (&foxH{id: identity.New("s")}).Handle(context.Background(), server, cfg) }()
	buf := make([]byte, 4096)
	n, _ := client.Read(buf)
	_ = client.Close()
	out := string(buf[:n])
	if !strings.HasPrefix(out, "fox a 0 -1 fox hello") || !strings.Contains(out, "station.name=s:") {
		t.Errorf("fox hello malformed: %q", out)
	}
}

func TestHARTIPSession(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: time.Second}
	resC := make(chan Result, 1)
	go func() {
		r, _ := (&hartIP{}).Handle(context.Background(), server, cfg)
		resC <- r
	}()
	// version=1, msgType=0 (request), msgID=0 (session-init), status=0,
	// seq=0x0001, byteCount=8.
	_, _ = client.Write([]byte{1, 0, 0, 0, 0, 1, 0, 8})
	buf := make([]byte, 16)
	n, _ := client.Read(buf)
	_ = client.Close()
	r := <-resC
	if n < 8 || buf[1] != 1 {
		t.Errorf("hartip response not a response frame: % x", buf[:n])
	}
	if r.Meta["hartip_msg_id"] != "session-initiate" {
		t.Errorf("hartip_msg_id = %v; want session-initiate", r.Meta["hartip_msg_id"])
	}
}

func TestPCWorxIdent(t *testing.T) {
	client, server := pipePair(t)
	cfg := config.Listener{ReadTimeout: time.Second}
	resC := make(chan Result, 1)
	go func() {
		r, _ := (&pcworx{}).Handle(context.Background(), server, cfg)
		resC <- r
	}()
	_, _ = client.Write([]byte{0x01, 0x01, 0x00, 0x1c})
	buf := make([]byte, 256)
	n, _ := client.Read(buf)
	_ = client.Close()
	r := <-resC
	if !strings.Contains(string(buf[:n]), "ILC 330 ETH") {
		t.Errorf("pcworx response missing model: % x", buf[:n])
	}
	if r.Meta["pcworx_model"] != "ILC 330 ETH" {
		t.Errorf("pcworx_model = %v", r.Meta["pcworx_model"])
	}
}
