package fingerprint

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strings"
)

// HASSH computes the SSH client KEX-init fingerprint from a raw SSH packet
// whose first byte is the SSH_MSG_KEXINIT (0x14). HASSH is a comma-joined
// MD5 of five client-side algorithm lists:
//
//	kex_algs;encryption_algs_c2s;mac_algs_c2s;compression_algs_c2s
//
// Empty / malformed input returns ("", "").
//
// SSH binary packet protocol prefix (RFC 4253 §6):
//
//	packet_length (4)  padding_length (1)  payload(packet_length-padding-1)  padding
//
// We accept either the raw payload starting with 0x14 (caller already
// stripped the framing) or the full binary packet.
func HASSH(buf []byte) (raw, hash string) {
	payload := buf
	if len(buf) >= 6 && buf[4] != 0x14 {
		// Possibly framed; try to skip the binary-packet header.
		pktLen := binary.BigEndian.Uint32(buf[0:4])
		padLen := int(buf[4])
		if 5+int(pktLen)-padLen <= len(buf) && int(pktLen) > padLen+1 {
			payload = buf[5 : 5+int(pktLen)-padLen-1]
		}
	}
	if len(payload) < 1+16 || payload[0] != 0x14 {
		return "", ""
	}
	// After type byte and 16-byte cookie come the name-lists.
	p := 1 + 16
	// Order: kex, server_host_key, encryption_c2s, encryption_s2c,
	//        mac_c2s, mac_s2c, compression_c2s, compression_s2c,
	//        languages_c2s, languages_s2c.
	names := make([]string, 0, 4)
	wanted := []int{0, 2, 4, 6} // kex / enc_c2s / mac_c2s / comp_c2s
	idx := 0
	for i := 0; i < 10 && p+4 <= len(payload); i++ {
		l := int(binary.BigEndian.Uint32(payload[p : p+4]))
		p += 4
		if p+l > len(payload) {
			return "", ""
		}
		if idx < len(wanted) && i == wanted[idx] {
			names = append(names, string(payload[p:p+l]))
			idx++
		}
		p += l
	}
	if len(names) != 4 {
		return "", ""
	}
	raw = strings.Join(names, ";")
	sum := md5.Sum([]byte(raw))
	return raw, hex.EncodeToString(sum[:])
}
