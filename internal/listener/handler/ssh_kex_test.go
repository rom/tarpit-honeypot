package handler

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// readSSHKexPayload reads one SSH binary packet from br and returns the
// payload (type byte + body, padding stripped).
func readSSHKexPayload(t *testing.T, br *bufio.Reader) []byte {
	t.Helper()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(br, hdr); err != nil {
		t.Fatalf("read kex header: %v", err)
	}
	pktLen := binary.BigEndian.Uint32(hdr[0:4])
	padLen := int(hdr[4])
	if pktLen < 2 || pktLen > 70000 {
		t.Fatalf("implausible packet_length %d", pktLen)
	}
	rest := make([]byte, int(pktLen)-1)
	if _, err := io.ReadFull(br, rest); err != nil {
		t.Fatalf("read kex body: %v", err)
	}
	if padLen > len(rest) {
		t.Fatalf("padding %d exceeds body %d", padLen, len(rest))
	}
	return rest[:len(rest)-padLen]
}

// The SSH handler must pipeline a KEXINIT after the banner, with an
// algorithm set consistent with the advertised version, and record the
// server HASSH.
func TestSSHServerKEXINIT(t *testing.T) {
	cases := []struct {
		banner      string
		mustContain []string
		mustNotHave []string
	}{
		{"SSH-2.0-OpenSSH_9.2p1 Debian-2", []string{"chacha20-poly1305@openssh.com", "sntrup761x25519-sha512@openssh.com"}, []string{"3des-cbc"}},
		{"SSH-2.0-OpenSSH_7.4", []string{"3des-cbc", "diffie-hellman-group1-sha1", "ssh-rsa"}, nil},
		{"SSH-2.0-dropbear_2019.78", []string{"aes128-ctr"}, []string{"chacha20-poly1305@openssh.com"}},
	}
	for _, c := range cases {
		client, server := pipePair(t)
		cfg := config.Listener{Banner: c.banner + "\r\n", ReadTimeout: 2 * time.Second}
		resC := make(chan Result, 1)
		go func() {
			r, _ := (&ssh{}).Handle(context.Background(), server, cfg)
			resC <- r
		}()
		br := bufio.NewReader(client)
		banner, _ := br.ReadString('\n')
		if !strings.HasPrefix(banner, c.banner) {
			t.Fatalf("banner = %q; want prefix %q", banner, c.banner)
		}
		payload := readSSHKexPayload(t, br)
		if len(payload) < 17 || payload[0] != 0x14 {
			t.Fatalf("%s: not a KEXINIT payload (first=0x%02x len=%d)", c.banner, payload[0], len(payload))
		}
		for _, want := range c.mustContain {
			if !bytes.Contains(payload, []byte(want)) {
				t.Errorf("%s: KEXINIT missing %q", c.banner, want)
			}
		}
		for _, no := range c.mustNotHave {
			if bytes.Contains(payload, []byte(no)) {
				t.Errorf("%s: KEXINIT unexpectedly contains %q", c.banner, no)
			}
		}
		_, _ = client.Write([]byte("SSH-2.0-probe\r\n"))
		_ = client.Close()
		r := <-resC
		if s, _ := r.Meta["hassh_server"].(string); len(s) != 32 {
			t.Errorf("%s: hassh_server = %q; want 32-char md5", c.banner, s)
		}
	}
}
