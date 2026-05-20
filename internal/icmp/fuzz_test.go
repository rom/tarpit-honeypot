package icmp

import "testing"

// FuzzICMPParsers feeds arbitrary bytes through every ICMP function that
// consumes attacker-controlled input — the anomaly detector plus the
// reply/echo builders that parse an incoming request. None may panic on a
// malformed / truncated ICMP message or IP header.
func FuzzICMPParsers(f *testing.F) {
	f.Add([]byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01})                                     // echo request
	f.Add([]byte{0x0d, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) // timestamp req
	f.Add([]byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01})                                     // v6 echo request
	f.Add([]byte{})
	f.Add([]byte{0x08})
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ICMP parser panicked on %d bytes: %v", len(data), r)
			}
		}()
		// Anomalies takes an IP header + ICMP message; split the input so
		// both halves get exercised with attacker bytes.
		k := 0
		if len(data) > 0 {
			k = int(data[0]) % (len(data) + 1)
		}
		_ = Anomalies(data[:k], data[k:])

		_ = EchoReplyV4(data)
		_ = EchoReplyV6(data)
		_ = TimestampReplyV4(data, 0)
		_ = AddrMaskReplyV4(data, [4]byte{255, 255, 255, 0})
		_ = DestUnreachableV4(0, data)
		_ = FragNeededV4(1500, data)
		_ = TimeExceededV4(0, data)
		_ = ParamProblemV4(0, data)
		_ = RedirectV4(0, [4]byte{10, 0, 0, 1}, data)
		_ = Valid(data)
	})
}
