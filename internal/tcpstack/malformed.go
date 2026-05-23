package tcpstack

// Classify inspects a parsed Segment for the malformed / illegal packet
// shapes a honeypot wants to record: corrupt checksums, truncated or
// dishonest headers, IP fragmentation (an evasion technique we don't
// reassemble), and the classic stealth-scan flag combinations nmap and
// hping use (NULL / FIN / Xmas / SYN-FIN / SYN-RST / data-in-SYN).
//
// It returns short stable markers (e.g. "tcp-xmas", "ip-bad-checksum")
// suitable for an event field and for the protocol-violation correlator.
// A well-formed, ordinary segment yields nil.
func Classify(s *Segment) []string {
	if s == nil {
		return nil
	}
	if s.IHL == 0 {
		// Bogus IHL: we never extracted a real header, so nothing else
		// can be trusted.
		return []string{"ip-bad-header-len"}
	}

	var m []string
	if !s.IPChecksumOK {
		m = append(m, "ip-bad-checksum")
	}
	if s.MF || s.FragOff != 0 {
		m = append(m, "ip-fragmented")
	}
	if !s.IsTCP {
		return m
	}
	if s.TCPShort {
		return append(m, "tcp-truncated")
	}
	if s.BadDataOff {
		// Header length lied, so the checksum could not be verified;
		// don't also report it as a bad checksum.
		m = append(m, "tcp-bad-dataoffset")
	} else if !s.TCPChecksumOK {
		m = append(m, "tcp-bad-checksum")
	}

	f := s.Flags
	syn := f&SYN != 0
	switch {
	case f == 0:
		m = append(m, "tcp-null")
	case syn && f&FIN != 0:
		m = append(m, "tcp-syn-fin")
	case syn && f&RST != 0:
		m = append(m, "tcp-syn-rst")
	}
	if f == FIN {
		m = append(m, "tcp-fin-scan")
	}
	if !syn && f&(FIN|PSH|URG) == (FIN|PSH|URG) {
		m = append(m, "tcp-xmas")
	}
	if syn && len(s.Payload) > 0 {
		m = append(m, "tcp-data-in-syn")
	}
	return m
}

// IsMalformed reports whether Classify would return any marker — a cheap
// gate for the responder's "drop, don't reply" decision on probe packets
// that should never get a polite SYN-ACK.
func IsMalformed(s *Segment) bool { return len(Classify(s)) > 0 }
