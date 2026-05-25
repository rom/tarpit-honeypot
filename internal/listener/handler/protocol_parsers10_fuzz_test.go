package handler

// Tenth batch: the classic inetd "small services" (RFC 862-868 / 1340 QOTD),
// both TCP and UDP. They are trivial but commonly probed; the honeypot's
// replies are bounded (never an amplifying stream), and these targets confirm
// the capture path never panics on arbitrary input.
//
//	go test ./internal/listener/handler -run x -fuzz FuzzEchoTCPHandler -fuzztime 30s

import "testing"

var inetdSeeds = [][]byte{
	[]byte("hello\r\n"),
	{0x00, 0x01, 0x02, 0x03},
	{},
}

func FuzzEchoTCPHandler(f *testing.F)    { fuzzTCPHandler(f, "echo", inetdSeeds...) }
func FuzzDiscardTCPHandler(f *testing.F) { fuzzTCPHandler(f, "discard", inetdSeeds...) }
func FuzzDaytimeTCPHandler(f *testing.F) { fuzzTCPHandler(f, "daytime", inetdSeeds...) }
func FuzzQOTDTCPHandler(f *testing.F)    { fuzzTCPHandler(f, "qotd", inetdSeeds...) }
func FuzzChargenTCPHandler(f *testing.F) { fuzzTCPHandler(f, "chargen", inetdSeeds...) }
func FuzzTimeTCPHandler(f *testing.F)    { fuzzTCPHandler(f, "time", inetdSeeds...) }

func FuzzEchoUDPHandler(f *testing.F)    { fuzzUDPHandler(f, "echo", inetdSeeds...) }
func FuzzDiscardUDPHandler(f *testing.F) { fuzzUDPHandler(f, "discard", inetdSeeds...) }
func FuzzDaytimeUDPHandler(f *testing.F) { fuzzUDPHandler(f, "daytime", inetdSeeds...) }
func FuzzQOTDUDPHandler(f *testing.F)    { fuzzUDPHandler(f, "qotd", inetdSeeds...) }
func FuzzChargenUDPHandler(f *testing.F) { fuzzUDPHandler(f, "chargen", inetdSeeds...) }
func FuzzTimeUDPHandler(f *testing.F)    { fuzzUDPHandler(f, "time", inetdSeeds...) }
