package handler

import (
	"bufio"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// ircH emulates an IRC server (TCP 6667). IRC is a long-running botnet C2
// channel (Mirai-era loaders, classic DDoS bots) and the home of the famous
// UnrealIRCd 3.2.8.1 backdoor (CVE-2010-2075). We greet like a real ircd,
// complete registration (NICK/USER → RPL_WELCOME burst) so a bot proceeds and
// reveals its channel/commands, capture a PASS credential, flag channel joins
// as C2, and recognize the UnrealIRCd backdoor trigger.
type ircH struct{}

func (ircH) Name() string { return "irc" }

func (ircH) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}

	// Real ircds send an AUTH notice burst before registration.
	greet := ":irc.local NOTICE AUTH :*** Looking up your hostname...\r\n" +
		":irc.local NOTICE AUTH :*** Found your hostname\r\n"
	if _, err := conn.Write([]byte(greet)); err != nil {
		res.Meta["write_err"] = err.Error()
		return res, nil
	}
	res.BannerSent = "irc NOTICE AUTH"

	br := bufio.NewReader(conn)
	var nick, user, channels []string
	var registered bool
	for i := 0; i < 12; i++ {
		line, err := readLineCapped(br, maxLineBytes)
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		res.Payload = append(res.Payload, []byte(line+"\n")...)

		// UnrealIRCd 3.2.8.1 backdoor (CVE-2010-2075): a line beginning with
		// "AB;" runs the remainder as a shell command on the server. No
		// legitimate IRC command looks like this.
		if strings.HasPrefix(line, "AB;") {
			res.CVEHits = appendUnique(res.CVEHits, "CVE-2010-2075")
			flagAnomaly(&res, "cve:CVE-2010-2075")
			flagAnomaly(&res, "irc-unrealircd-backdoor")
			res.Meta["backdoor_command"] = strings.TrimPrefix(line, "AB;")
			res.Meta["intent"] = "UnrealIRCd 3.2.8.1 backdoor command execution (CVE-2010-2075)"
			continue
		}

		verb, args := ircSplit(line)
		switch strings.ToUpper(verb) {
		case "NICK":
			nick = appendUnique(nick, args)
		case "USER":
			if f := strings.Fields(args); len(f) > 0 {
				user = appendUnique(user, f[0])
			}
		case "PASS":
			res.Meta["irc_password"] = args
			flagAnomaly(&res, "irc-password")
			flagDefaultCred(&res, "", args)
		case "JOIN":
			for _, ch := range strings.Split(args, ",") {
				ch = strings.TrimSpace(strings.Fields(ch)[0])
				if ch != "" {
					channels = appendUnique(channels, ch)
				}
			}
			flagAnomaly(&res, "irc-channel-join")
			if res.Meta["intent"] == nil {
				res.Meta["intent"] = "IRC channel join — bot/botnet C2 rendezvous"
			}
		case "PRIVMSG":
			flagAnomaly(&res, "irc-privmsg")
		case "OPER":
			flagAnomaly(&res, "irc-oper-attempt")
		}

		// Once we have NICK+USER, send the welcome burst so a bot continues.
		if !registered && len(nick) > 0 && len(user) > 0 {
			n := nick[len(nick)-1]
			welcome := ":irc.local 001 " + n + " :Welcome to the Internet Relay Network " + n + "\r\n" +
				":irc.local 002 " + n + " :Your host is irc.local, running version Unreal3.2.8.1\r\n" +
				":irc.local 004 " + n + " irc.local Unreal3.2.8.1 iowghraAsORTVSxNCWqBzvdHtGp\r\n"
			_, _ = conn.Write([]byte(welcome))
			res.BannerSent = "irc 001 welcome"
			registered = true
		}
	}
	if len(nick) > 0 {
		res.Meta["irc_nick"] = nick
	}
	if len(user) > 0 {
		res.Meta["irc_user"] = user
	}
	if len(channels) > 0 {
		res.Meta["irc_channels"] = channels
	}
	return res, nil
}

// ircSplit splits an IRC line into its command verb and the remaining args.
func ircSplit(line string) (verb, args string) {
	if i := strings.IndexByte(line, ' '); i >= 0 {
		return line[:i], strings.TrimSpace(line[i+1:])
	}
	return line, ""
}
