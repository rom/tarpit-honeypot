// Package tcpstack is a minimal userspace TCP/IPv4 engine for the honeynet
// TUN decoy. It is NOT a general-purpose stack: it exists to make virtual
// honeynet hosts (a) complete TCP handshakes and answer a single
// request/response so a scanner sees a believable open service without the
// operator running `ip addr add` per host, (b) shape the synthesized
// IP/TCP responses to match a target OS's stack fingerprint (TTL, window,
// MSS, window-scale, SACK, timestamps, option order — what nmap -O / p0f
// read), and (c) recognize malformed / illegal packets and surface them.
//
// Deliberately simplified for a decoy: in-order data only, no
// retransmission, congestion control, or out-of-order reassembly. A lost
// segment just makes the scanner retry (a fresh flow). All logic here is
// pure and table-driven so it is fully unit-testable with synthetic
// packets; the Linux TUN I/O that feeds it lives in internal/tunnet.
package tcpstack

// TCP flag bits.
const (
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
	URG = 0x20
	ECE = 0x40
	CWR = 0x80
)

// TCP option kinds we synthesize (subset of IANA).
const (
	optEOL       = 0
	optNOP       = 1
	optMSS       = 2
	optWScale    = 3
	optSACKPerm  = 4
	optTimestamp = 8
)

// OSProfile shapes synthesized TCP/IP responses so a virtual host
// fingerprints as the intended OS. The fields mirror the SYN-ACK
// characteristics nmap's OS-detection and p0f key on.
type OSProfile struct {
	Name   string
	TTL    uint8  // initial IP TTL
	Window uint16 // advertised TCP window in the SYN-ACK
	MSS    uint16 // maximum segment size option (0 = omit)
	WScale uint8  // window-scale shift; only emitted when HasWScale
	DF     bool   // set the IP Don't-Fragment bit

	HasWScale bool
	SACKPerm  bool // emit a SACK-permitted option
	HasTS     bool // emit a timestamps option

	// Order is the option layout (kinds), letting us reproduce a vendor's
	// exact ordering + NOP padding — a strong fingerprint signal.
	Order []byte
}

// profiles are canonical SYN-ACK fingerprints. Values approximate the real
// stacks closely enough to fool nmap/p0f signature matching for a decoy.
var profiles = map[string]OSProfile{
	"linux": {
		Name: "linux", TTL: 64, Window: 64240, MSS: 1460, WScale: 7, DF: true,
		HasWScale: true, SACKPerm: true, HasTS: true,
		Order: []byte{optMSS, optSACKPerm, optTimestamp, optNOP, optWScale},
	},
	"windows": {
		Name: "windows", TTL: 128, Window: 65535, MSS: 1460, WScale: 8, DF: true,
		HasWScale: true, SACKPerm: true, HasTS: false,
		Order: []byte{optMSS, optNOP, optWScale, optNOP, optNOP, optSACKPerm},
	},
	"bsd": {
		Name: "bsd", TTL: 64, Window: 65535, MSS: 1460, WScale: 6, DF: true,
		HasWScale: true, SACKPerm: true, HasTS: true,
		Order: []byte{optMSS, optNOP, optWScale, optSACKPerm, optTimestamp},
	},
	// Embedded / OT / network gear: small window, no scaling/SACK/TS, TTL 255.
	"ot": {
		Name: "ot", TTL: 255, Window: 4096, MSS: 1460, WScale: 0, DF: false,
		HasWScale: false, SACKPerm: false, HasTS: false,
		Order: []byte{optMSS},
	},
}

// ProfileFor maps an archetype family / OS name to the closest stack
// fingerprint. Unknown families default to the Linux profile.
func ProfileFor(family string) OSProfile {
	switch normFamily(family) {
	case "windows":
		return profiles["windows"]
	case "bsd", "freebsd", "openbsd", "netbsd", "darwin", "macos", "pfsense", "truenas", "opnsense":
		return profiles["bsd"]
	case "ot", "ics", "embedded", "moxa", "siemens", "cisco",
		"hirschmann", "westermo", "phoenix", "schneider", "omron", "mitsubishi",
		"abb", "beckhoff", "honeywell", "wago", "advantech", "teltonika":
		return profiles["ot"]
	default:
		return profiles["linux"]
	}
}

func normFamily(f string) string {
	out := make([]byte, 0, len(f))
	for i := 0; i < len(f); i++ {
		c := f[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		out = append(out, c)
	}
	return string(out)
}

// buildOptions serializes the profile's TCP options (for a SYN-ACK),
// padded to a 4-byte boundary. tsVal/tsEcr fill the timestamp option when
// present. Returns the option bytes (always a multiple of 4).
func (p OSProfile) buildOptions(tsVal, tsEcr uint32) []byte {
	var b []byte
	for _, k := range p.Order {
		switch k {
		case optMSS:
			if p.MSS == 0 {
				continue
			}
			b = append(b, optMSS, 4, byte(p.MSS>>8), byte(p.MSS))
		case optWScale:
			if !p.HasWScale {
				continue
			}
			b = append(b, optWScale, 3, p.WScale)
		case optSACKPerm:
			if !p.SACKPerm {
				continue
			}
			b = append(b, optSACKPerm, 2)
		case optTimestamp:
			if !p.HasTS {
				continue
			}
			b = append(b, optTimestamp, 10,
				byte(tsVal>>24), byte(tsVal>>16), byte(tsVal>>8), byte(tsVal),
				byte(tsEcr>>24), byte(tsEcr>>16), byte(tsEcr>>8), byte(tsEcr))
		case optNOP:
			b = append(b, optNOP)
		case optEOL:
			b = append(b, optEOL)
		}
	}
	for len(b)%4 != 0 { // pad to a 32-bit boundary with NOPs
		b = append(b, optNOP)
	}
	return b
}
