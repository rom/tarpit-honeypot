package artifactscan

import (
	"sort"
	"strings"
)

// Linux-dropper / commodity-malware family classification. Honeypots mostly
// catch loader scripts and botnet binaries, not bespoke implants, so a small
// behavioural-signature table attributes the usual families (Mirai & its forks,
// XorDDoS, Kinsing, coinminers, IRC bots, Mozi) from the strings in the artifact
// — or in its deobfuscated inner layer. Detection only; nothing is executed.

type dropperSig struct {
	family  string
	markers []string // lowercase substrings; distinct hits are scored
	min     int      // minimum distinct marker hits to attribute
}

var dropperSigs = []dropperSig{
	{"mirai", []string{"busybox", "/dev/watchdog", "/dev/misc/watchdog", "mirai", "tsource engine query", "/bin/busybox echo", "ncorrect", "lcogqgptgp"}, 2},
	{"gafgyt/bashlite", []string{"getlocalip", "httpflood", "udpflood", "tcpflood", "/bin/busybox", "ping", "stdhex", "vseattack"}, 3},
	{"xorddos", []string{"/var/run/gcc.pid", "cat resolv.conf", "md5=", "hidden", "/lib/libudev.so", "cmd.go", "crondtab", "kill -9"}, 3},
	{"kinsing", []string{"kdevtmpfsi", "kinsing", "/tmp/kdevtmpfsi", "kdevtmpfsi.lock"}, 1},
	{"coinminer", []string{"xmrig", "stratum+tcp", "stratum+ssl", "donate-level", "cryptonight", "randomx", "minerd", "--coin", "nanopool", "supportxmr", "pool.", "hashvault"}, 2},
	{"irc-bot", []string{"privmsg", "nick ", "join #", " pong ", "ping :", "oper ", "channel"}, 3},
	{"mozi", []string{"mozi.m", "mozi.a", "/mozi", "[nd]", "dht"}, 2},
	{"perl-shellbot", []string{"io::socket", "use socket", "$irc", "connect(", "fork()", "sub conn"}, 3},
	{"generic-loader", []string{"wget ", "curl ", "chmod +x", "chmod 777", "rm -rf", "tftp ", "/tmp/", "nohup ", "./"}, 4},
}

// ClassifyDropper attributes a malware family from the artifact bytes. It
// returns the best-scoring family and the distinct markers that matched, or
// ("", nil) when nothing scores above its family threshold.
func ClassifyDropper(data []byte) (family string, markers []string) {
	low := strings.ToLower(string(data))
	bestScore := 0
	for _, sig := range dropperSigs {
		var hit []string
		for _, m := range sig.markers {
			if strings.Contains(low, m) {
				hit = append(hit, strings.TrimSpace(m))
			}
		}
		// "generic-loader" is the weakest attribution — only win if no named
		// family did, so a real Mirai loader isn't mislabelled generic.
		score := len(hit)
		if sig.family == "generic-loader" {
			score = len(hit) - 1
		}
		if len(hit) >= sig.min && score > bestScore {
			bestScore = score
			family = sig.family
			markers = hit
		}
	}
	sort.Strings(markers)
	return family, markers
}
