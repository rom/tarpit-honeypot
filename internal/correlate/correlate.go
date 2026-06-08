// Package correlate maintains short-lived in-memory state across events to
// detect port-scans, brute-force attempts (with credential extraction),
// and long-window slow scans from a single source.
//
// Each call to Observe returns the original event plus any aggregate events
// that fired as a result. Concurrent-safe via a single per-correlator mutex.
package correlate

import (
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

type Correlator struct {
	cfg       config.Correlate
	scanSev   event.Severity
	bruteSev  event.Severity
	slowSev   event.Severity
	sweepSev  event.Severity
	spraySev  event.Severity
	reuseSev  event.Severity
	pathSev   event.Severity
	dnsSev    event.Severity
	beaconSev event.Severity
	// Additional opt-in correlators.
	hostSweepSev   event.Severity
	crossTargetSev event.Severity
	svcSweepSev    event.Severity
	uaRotSev       event.Severity
	exploitSev     event.Severity
	icsSev         event.Severity
	canarySev      event.Severity
	fpReuseSev     event.Severity
	protoViolSev   event.Severity
	exfilSev       event.Severity
	floodSev       event.Severity
	lateralSev     event.Severity
	otReconSev     event.Severity
	dataAccSev     event.Severity
	malwareSev     event.Severity
	webshellSev    event.Severity
	tiBurstSev     event.Severity
	geoVelSev      event.Severity
	ampSev         event.Severity
	defCredSev     event.Severity
	cveCampSev     event.Severity
	destructSev    event.Severity
	cloudCredSev   event.Severity
	ssrfCbSev      event.Severity
	mitmCapSev     event.Severity
	fpRotSev       event.Severity
	ctrTakeSev     event.Severity
	webProbeSev    event.Severity
	sshKeySev      event.Severity
	spamRelaySev   event.Severity
	dnsTunnelSev   event.Severity
	reconExpSev    event.Severity
	honeytokenSev  event.Severity
	toolRotSev     event.Severity
	plcProgSev     event.Severity
	modeChgSev     event.Severity
	otKillSev      event.Severity
	remoteToolSev  event.Severity
	oobMgmtSev     event.Severity
	remoteExecSev  event.Severity
	tollFraudSev   event.Severity
	voipEnumSev    event.Severity
	pbxCtrlSev     event.Severity

	mu       sync.Mutex
	scan     map[string]*scanState      // key: source IP
	brute    map[string]*bruteState     // key: source IP (+ ":<port>" if PerPort)
	slow     map[string]*slowState      // key: source IP
	sweep    map[string]*sweepState     // key: source IP
	spray    map[string]*sprayState     // key: source IP
	reuse    map[string]*reuseState     // key: credential pair
	pathEnum map[string]*setState       // key: source IP (distinct HTTP paths)
	dnsEnum  map[string]*setState       // key: source IP (distinct DNS names)
	beacon   map[string]*beaconState    // key: source IP (call-home timestamps)
	story    map[string]*storylineState // key: source IP
	// Additional opt-in correlator state.
	hostSweep   map[string]*setState       // key: source IP (distinct dest hosts)
	crossTarget map[string]*targetSeqState // key: source IP (per-target order/timing/ports)
	svcSweep    map[string]*setState       // key: source IP (distinct handlers)
	uaRot       map[string]*setState       // key: source IP (distinct user-agents)
	exploit     map[string]*setState       // key: source IP (distinct CVE ids)
	ics         map[string]*countState     // key: source IP (control-command count)
	canary      map[string]*setState       // key: source IP (distinct canary tokens)
	fpReuse     map[string]*reuseState     // key: fingerprint value (distinct sources)
	protoViol   map[string]*setState       // key: source IP (distinct anomaly markers)
	exfil       map[string]*byteState      // key: source IP (cumulative request bytes)
	flood       map[string]*countState     // key: source IP (connection count)
	lateral     map[string]*setState       // key: source IP (distinct lateral handlers)
	otRecon     map[string]*setState       // key: source IP (distinct ICS handlers)
	dataAcc     map[string]*countState     // key: source IP (data-access event count)
	malware     map[string]*countState     // key: source IP (malware:capture count)
	webshell    map[string]*countState     // key: source IP (webshell event count)
	tiBurst     map[string]*countState     // key: source IP (threat-listed/Tor event count)
	geoVel      map[string]*setState       // key: credential pair (distinct countries)
	amp         map[string]*setState       // key: source IP (distinct amplifier services)
	defCred     map[string]*setState       // key: source IP (distinct default-cred services)
	cveCamp     map[string]*reuseState     // key: cve id (distinct source IPs)
	destruct    map[string]*countState     // key: source IP (data-destruction op count)
	cloudCred   map[string]*countState     // key: source IP (cloud cred-theft op count)
	ssrfCb      map[string]*setState       // key: source IP (distinct ssrf tokens)
	mitmCap     map[string]*countState     // key: source IP (tls-decrypted exploit/cred count)
	fpRot       map[string]*setState       // key: source IP (distinct network fingerprints)
	ctrTake     map[string]*setState       // key: source IP (distinct container/k8s control ops)
	webProbe    map[string]*setState       // key: source IP (distinct webapp:* attack classes)
	sshKey      map[string]*setState       // key: source IP (distinct offered SSH pubkeys)
	spamRelay   map[string]*countState     // key: source IP (open-relay / rcpt-enum attempts)
	dnsTunnel   map[string]*countState     // key: source IP (DNS tunnel/DGA anomaly count)
	reconExp    map[string]*setState       // key: source IP (recon-then-exploit progression)
	honeytoken  map[string]*reuseState     // key: canary token id (distinct source IPs)
	toolRot     map[string]*setState       // key: source IP (distinct attack tools)
	plcProg     map[string]*countState     // key: source IP (program-download count)
	modeChg     map[string]*countState     // key: source IP (mode-change count)
	otKill      map[string]*setState       // key: source IP (recon+control tokens)
	remoteTool  map[string]*setState       // key: source IP (distinct remote tools)
	oobMgmt     map[string]*setState       // key: source IP (distinct OOB mgmt surfaces)
	remoteExec  map[string]*countState     // key: source IP (cleartext remote-exec count)
	tollFraud   map[string]*countState     // key: source IP (call-placement count)
	voipEnum    map[string]*setState       // key: source IP (distinct VoIP protocols)
	pbxCtrl     map[string]*countState     // key: source IP (PBX admin-action count)
	emitted     map[string]time.Time       // dedup of aggregate emission
	lastGC      time.Time                  // last idle-state sweep
}

// countState tracks a per-source count within a window (control commands,
// connection volume). byteState tracks cumulative bytes within a window.
type countState struct {
	since time.Time
	count int
}

type byteState struct {
	since time.Time
	bytes int64
}

// beaconState holds the recent contact timestamps for one source so the
// inter-arrival regularity (C2 beacon jitter) can be measured.
type beaconState struct {
	times []time.Time
}

// setState tracks a per-source set of distinct strings within a window
// (HTTP paths / DNS names), capped to bound memory.
type setState struct {
	since time.Time
	set   map[string]struct{}
}

// sprayState tracks the distinct usernames one source has tried (password
// spraying). reuseState tracks the distinct source IPs that have tried one
// credential pair (credential stuffing). Both sets are capped to bound
// memory under sustained abuse.
type sprayState struct {
	since time.Time
	users map[string]struct{}
}

type reuseState struct {
	since   time.Time
	sources map[string]struct{}
}

const corrSetCap = 256

type scanState struct {
	since time.Time
	ports map[int]struct{}
}

type bruteState struct {
	since time.Time
	count int
	// creds is a per-source set of unique credential pairs seen. Capped at
	// 50 to avoid unbounded growth under a long brute-force.
	creds map[string]struct{}
}

type slowState struct {
	firstSeen time.Time
	lastSeen  time.Time
	ports     map[int]time.Time // port -> first-seen
}

type sweepState struct {
	since time.Time
	ips   map[string]struct{} // distinct destination IPs touched via ICMP
}

func New(cfg config.Correlate) (*Correlator, error) {
	c := &Correlator{
		cfg:         cfg,
		scan:        map[string]*scanState{},
		brute:       map[string]*bruteState{},
		slow:        map[string]*slowState{},
		sweep:       map[string]*sweepState{},
		spray:       map[string]*sprayState{},
		reuse:       map[string]*reuseState{},
		pathEnum:    map[string]*setState{},
		dnsEnum:     map[string]*setState{},
		beacon:      map[string]*beaconState{},
		story:       map[string]*storylineState{},
		hostSweep:   map[string]*setState{},
		crossTarget: map[string]*targetSeqState{},
		svcSweep:    map[string]*setState{},
		uaRot:       map[string]*setState{},
		exploit:     map[string]*setState{},
		ics:         map[string]*countState{},
		canary:      map[string]*setState{},
		fpReuse:     map[string]*reuseState{},
		protoViol:   map[string]*setState{},
		exfil:       map[string]*byteState{},
		flood:       map[string]*countState{},
		lateral:     map[string]*setState{},
		otRecon:     map[string]*setState{},
		dataAcc:     map[string]*countState{},
		malware:     map[string]*countState{},
		webshell:    map[string]*countState{},
		tiBurst:     map[string]*countState{},
		geoVel:      map[string]*setState{},
		amp:         map[string]*setState{},
		defCred:     map[string]*setState{},
		cveCamp:     map[string]*reuseState{},
		destruct:    map[string]*countState{},
		cloudCred:   map[string]*countState{},
		ssrfCb:      map[string]*setState{},
		mitmCap:     map[string]*countState{},
		fpRot:       map[string]*setState{},
		ctrTake:     map[string]*setState{},
		webProbe:    map[string]*setState{},
		sshKey:      map[string]*setState{},
		spamRelay:   map[string]*countState{},
		dnsTunnel:   map[string]*countState{},
		reconExp:    map[string]*setState{},
		honeytoken:  map[string]*reuseState{},
		toolRot:     map[string]*setState{},
		plcProg:     map[string]*countState{},
		modeChg:     map[string]*countState{},
		otKill:      map[string]*setState{},
		remoteTool:  map[string]*setState{},
		oobMgmt:     map[string]*setState{},
		remoteExec:  map[string]*countState{},
		tollFraud:   map[string]*countState{},
		voipEnum:    map[string]*setState{},
		pbxCtrl:     map[string]*countState{},
		emitted:     map[string]time.Time{},
	}
	if cfg.PortScan.Enabled {
		s, err := event.ParseSeverity(cfg.PortScan.Severity)
		if err != nil {
			return nil, err
		}
		c.scanSev = s
	}
	if cfg.BruteForce.Enabled {
		s, err := event.ParseSeverity(cfg.BruteForce.Severity)
		if err != nil {
			return nil, err
		}
		c.bruteSev = s
	}
	if cfg.SlowScan.Enabled {
		s, err := event.ParseSeverity(cfg.SlowScan.Severity)
		if err != nil {
			return nil, err
		}
		c.slowSev = s
	}
	if cfg.ICMPSweep.Enabled {
		s, err := event.ParseSeverity(cfg.ICMPSweep.Severity)
		if err != nil {
			return nil, err
		}
		c.sweepSev = s
	}
	if cfg.PasswordSpray.Enabled {
		s, err := event.ParseSeverity(cfg.PasswordSpray.Severity)
		if err != nil {
			return nil, err
		}
		c.spraySev = s
	}
	if cfg.CredReuse.Enabled {
		s, err := event.ParseSeverity(cfg.CredReuse.Severity)
		if err != nil {
			return nil, err
		}
		c.reuseSev = s
	}
	if cfg.PathEnum.Enabled {
		s, err := event.ParseSeverity(cfg.PathEnum.Severity)
		if err != nil {
			return nil, err
		}
		c.pathSev = s
	}
	if cfg.DNSEnum.Enabled {
		s, err := event.ParseSeverity(cfg.DNSEnum.Severity)
		if err != nil {
			return nil, err
		}
		c.dnsSev = s
	}
	if cfg.Beacon.Enabled {
		s, err := event.ParseSeverity(cfg.Beacon.Severity)
		if err != nil {
			return nil, err
		}
		c.beaconSev = s
	}
	// Additional opt-in correlators: parse each enabled detector's severity.
	for _, sp := range []struct {
		on  bool
		sev string
		dst *event.Severity
	}{
		{cfg.HostSweep.Enabled, cfg.HostSweep.Severity, &c.hostSweepSev},
		{cfg.CrossTarget.Enabled, cfg.CrossTarget.Severity, &c.crossTargetSev},
		{cfg.ServiceSweep.Enabled, cfg.ServiceSweep.Severity, &c.svcSweepSev},
		{cfg.UARotation.Enabled, cfg.UARotation.Severity, &c.uaRotSev},
		{cfg.ExploitChain.Enabled, cfg.ExploitChain.Severity, &c.exploitSev},
		{cfg.ICSControl.Enabled, cfg.ICSControl.Severity, &c.icsSev},
		{cfg.CanaryTrip.Enabled, cfg.CanaryTrip.Severity, &c.canarySev},
		{cfg.FingerprintReuse.Enabled, cfg.FingerprintReuse.Severity, &c.fpReuseSev},
		{cfg.ProtocolViolation.Enabled, cfg.ProtocolViolation.Severity, &c.protoViolSev},
		{cfg.Exfil.Enabled, cfg.Exfil.Severity, &c.exfilSev},
		{cfg.SessionFlood.Enabled, cfg.SessionFlood.Severity, &c.floodSev},
		{cfg.LateralMovement.Enabled, cfg.LateralMovement.Severity, &c.lateralSev},
		{cfg.OTRecon.Enabled, cfg.OTRecon.Severity, &c.otReconSev},
		{cfg.DataAccess.Enabled, cfg.DataAccess.Severity, &c.dataAccSev},
		{cfg.MalwareCampaign.Enabled, cfg.MalwareCampaign.Severity, &c.malwareSev},
		{cfg.Webshell.Enabled, cfg.Webshell.Severity, &c.webshellSev},
		{cfg.ThreatIntelBurst.Enabled, cfg.ThreatIntelBurst.Severity, &c.tiBurstSev},
		{cfg.GeoVelocity.Enabled, cfg.GeoVelocity.Severity, &c.geoVelSev},
		{cfg.AmplificationProbe.Enabled, cfg.AmplificationProbe.Severity, &c.ampSev},
		{cfg.DefaultCredSweep.Enabled, cfg.DefaultCredSweep.Severity, &c.defCredSev},
		{cfg.CVECampaign.Enabled, cfg.CVECampaign.Severity, &c.cveCampSev},
		{cfg.DestructiveAction.Enabled, cfg.DestructiveAction.Severity, &c.destructSev},
		{cfg.CloudCredTheft.Enabled, cfg.CloudCredTheft.Severity, &c.cloudCredSev},
		{cfg.SSRFCallback.Enabled, cfg.SSRFCallback.Severity, &c.ssrfCbSev},
		{cfg.TLSMITMCapture.Enabled, cfg.TLSMITMCapture.Severity, &c.mitmCapSev},
		{cfg.FingerprintRotation.Enabled, cfg.FingerprintRotation.Severity, &c.fpRotSev},
		{cfg.ContainerTakeover.Enabled, cfg.ContainerTakeover.Severity, &c.ctrTakeSev},
		{cfg.WebAttackProbe.Enabled, cfg.WebAttackProbe.Severity, &c.webProbeSev},
		{cfg.SSHKeySpray.Enabled, cfg.SSHKeySpray.Severity, &c.sshKeySev},
		{cfg.SpamRelay.Enabled, cfg.SpamRelay.Severity, &c.spamRelaySev},
		{cfg.DNSTunnel.Enabled, cfg.DNSTunnel.Severity, &c.dnsTunnelSev},
		{cfg.ReconToExploit.Enabled, cfg.ReconToExploit.Severity, &c.reconExpSev},
		{cfg.HoneytokenSpread.Enabled, cfg.HoneytokenSpread.Severity, &c.honeytokenSev},
		{cfg.ToolRotation.Enabled, cfg.ToolRotation.Severity, &c.toolRotSev},
		{cfg.PLCProgramDownload.Enabled, cfg.PLCProgramDownload.Severity, &c.plcProgSev},
		{cfg.ICSModeChange.Enabled, cfg.ICSModeChange.Severity, &c.modeChgSev},
		{cfg.OTKillChain.Enabled, cfg.OTKillChain.Severity, &c.otKillSev},
		{cfg.RemoteToolSweep.Enabled, cfg.RemoteToolSweep.Severity, &c.remoteToolSev},
		{cfg.OOBMgmtAccess.Enabled, cfg.OOBMgmtAccess.Severity, &c.oobMgmtSev},
		{cfg.RemoteExecCommand.Enabled, cfg.RemoteExecCommand.Severity, &c.remoteExecSev},
		{cfg.TollFraud.Enabled, cfg.TollFraud.Severity, &c.tollFraudSev},
		{cfg.VoIPEnum.Enabled, cfg.VoIPEnum.Severity, &c.voipEnumSev},
		{cfg.PBXControl.Enabled, cfg.PBXControl.Severity, &c.pbxCtrlSev},
	} {
		if !sp.on {
			continue
		}
		s, err := event.ParseSeverity(sp.sev)
		if err != nil {
			return nil, err
		}
		*sp.dst = s
	}
	return c, nil
}

// Observe ingests an event and returns it plus any aggregate events that
// fired. Always returns at least one event (the original).
func (c *Correlator) Observe(ev *event.Event) []*event.Event {
	out := []*event.Event{ev}
	if ev.Source.IP == "" {
		return out
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := ev.Time
	if now.IsZero() {
		now = time.Now().UTC()
	}
	c.gc(now)

	// ICMP sweep is checked first because ICMP events carry no dest
	// port — they'd be dropped by the port-requiring guard below.
	if c.cfg.ICMPSweep.Enabled && ev.Proto == "icmp" {
		if extra := c.checkSweep(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	// Threat-intel burst keys on source reputation (enrichment), not a
	// port, so it runs before the port guard to catch every flagged event.
	if c.cfg.ThreatIntelBurst.Enabled {
		if extra := c.checkThreatIntelBurst(ev, now); extra != nil {
			out = append(out, extra)
		}
	}

	// Everything past here keys on a destination port.
	if ev.Dest.Port == 0 {
		// Still feed the storyline correlator (it keys on tactics, not
		// ports) before returning.
		if extra := c.observeStoryline(ev, now); extra != nil {
			out = append(out, extra)
		}
		return out
	}

	if c.cfg.PortScan.Enabled {
		if extra := c.checkScan(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.BruteForce.Enabled {
		if extra := c.checkBrute(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.PasswordSpray.Enabled {
		if extra := c.checkSpray(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.CredReuse.Enabled {
		if extra := c.checkReuse(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.GeoVelocity.Enabled {
		if extra := c.checkGeoVelocity(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.AmplificationProbe.Enabled {
		if extra := c.checkAmplificationProbe(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.DefaultCredSweep.Enabled {
		if extra := c.checkDefaultCredSweep(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.CVECampaign.Enabled {
		if extra := c.checkCVECampaign(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.DestructiveAction.Enabled {
		if extra := c.checkDestructiveAction(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.CloudCredTheft.Enabled {
		if extra := c.checkCloudCredTheft(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.SSRFCallback.Enabled {
		if extra := c.checkSSRFCallback(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.TLSMITMCapture.Enabled {
		if extra := c.checkTLSMITMCapture(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.FingerprintRotation.Enabled {
		if extra := c.checkFingerprintRotation(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.ContainerTakeover.Enabled {
		if extra := c.checkContainerTakeover(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.WebAttackProbe.Enabled {
		if extra := c.checkWebAttackProbe(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.SSHKeySpray.Enabled {
		if extra := c.checkSSHKeySpray(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.SpamRelay.Enabled {
		if extra := c.checkSpamRelay(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.DNSTunnel.Enabled {
		if extra := c.checkDNSTunnel(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.ReconToExploit.Enabled {
		if extra := c.checkReconToExploit(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.HoneytokenSpread.Enabled {
		if extra := c.checkHoneytokenSpread(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.ToolRotation.Enabled {
		if extra := c.checkToolRotation(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.PLCProgramDownload.Enabled {
		if extra := c.checkPLCProgramDownload(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.ICSModeChange.Enabled {
		if extra := c.checkICSModeChange(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.OTKillChain.Enabled {
		if extra := c.checkOTKillChain(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.RemoteToolSweep.Enabled {
		if extra := c.checkRemoteToolSweep(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.OOBMgmtAccess.Enabled {
		if extra := c.checkOOBMgmtAccess(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.RemoteExecCommand.Enabled {
		if extra := c.checkRemoteExecCommand(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.TollFraud.Enabled {
		if extra := c.checkTollFraud(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.VoIPEnum.Enabled {
		if extra := c.checkVoIPEnum(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.PBXControl.Enabled {
		if extra := c.checkPBXControl(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.SlowScan.Enabled {
		if extra := c.checkSlowScan(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.PathEnum.Enabled {
		if extra := c.checkPathEnum(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.DNSEnum.Enabled {
		if extra := c.checkDNSEnum(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.Beacon.Enabled {
		if extra := c.checkBeacon(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.HostSweep.Enabled {
		if extra := c.checkHostSweep(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.CrossTarget.Enabled {
		if extra := c.checkCrossTarget(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.ServiceSweep.Enabled {
		if extra := c.checkServiceSweep(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.UARotation.Enabled {
		if extra := c.checkUARotation(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.ExploitChain.Enabled {
		if extra := c.checkExploitChain(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.ICSControl.Enabled {
		if extra := c.checkICSControl(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.CanaryTrip.Enabled {
		if extra := c.checkCanaryTrip(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.FingerprintReuse.Enabled {
		if extra := c.checkFingerprintReuse(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.ProtocolViolation.Enabled {
		if extra := c.checkProtocolViolation(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.Exfil.Enabled {
		if extra := c.checkExfil(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.SessionFlood.Enabled {
		if extra := c.checkSessionFlood(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.LateralMovement.Enabled {
		if extra := c.checkLateralMovement(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.OTRecon.Enabled {
		if extra := c.checkOTRecon(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.DataAccess.Enabled {
		if extra := c.checkDataAccess(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.MalwareCampaign.Enabled {
		if extra := c.checkMalwareCampaign(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if c.cfg.Webshell.Enabled {
		if extra := c.checkWebshell(ev, now); extra != nil {
			out = append(out, extra)
		}
	}
	if extra := c.observeStoryline(ev, now); extra != nil {
		out = append(out, extra)
	}
	return out
}

// checkBeacon detects regularly-spaced call-home contact from one source.
// After MinHits samples in the window it measures inter-arrival jitter
// (stddev/mean); a low jitter over a non-trivial mean interval is a C2
// beacon. Called with c.mu held.
func (c *Correlator) checkBeacon(ev *event.Event, now time.Time) *event.Event {
	cfg := c.cfg.Beacon
	st, ok := c.beacon[ev.Source.IP]
	if !ok {
		st = &beaconState{}
		c.beacon[ev.Source.IP] = st
	}
	// Keep only in-window samples, then record this contact (bounded).
	cutoff := now.Add(-cfg.Window)
	kept := st.times[:0]
	for _, t := range st.times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	st.times = append(kept, now)
	if len(st.times) > 128 {
		st.times = st.times[len(st.times)-128:]
	}
	if len(st.times) < cfg.MinHits {
		return nil
	}
	mean, jitterPct, ok := intervalRegularity(st.times)
	if !ok || mean < time.Second {
		// Ignore bursts (sub-second mean) — a beacon is a periodic call-home,
		// not a flood; those are caught by the scan / enumeration detectors.
		return nil
	}
	// Two flavors of periodicity:
	//   strict   — low stddev/mean jitter (a fixed-interval beacon).
	//   jittered — the intervals are noisy enough to pass the strict test but
	//              still cluster in a tight band (max/min <= beaconBandRatio).
	//              This catches C2 sleep-with-jitter (Cobalt Strike / Sliver,
	//              where ~37% jitter pushes stddev past MaxJitterPct). Needs more
	//              samples to keep the looser test from firing on coincidence.
	jittered := false
	switch {
	case jitterPct <= cfg.MaxJitterPct:
		// strict beacon
	case len(st.times) >= maxInt(cfg.MinHits, 8) && intervalBandRatio(st.times) <= beaconBandRatio:
		jittered = true
	default:
		return nil
	}
	if !c.shouldEmit("beacon|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:beacon",
		Severity: c.beaconSev,
		Source:   ev.Source,
		Dest:     event.Endpoint{Port: ev.Dest.Port},
		Proto:    ev.Proto,
		Handler:  ev.Handler,
		Meta: map[string]any{
			"interval_s": int(mean.Seconds()),
			"jitter_pct": jitterPct,
			"jittered":   jittered,
			"samples":    len(st.times),
			"window_s":   int(cfg.Window.Seconds()),
		},
	}
}

// beaconBandRatio bounds the jittered-beacon test: the largest inter-arrival
// interval may be at most this multiple of the smallest. A sleep S with jitter J
// gives intervals in [S(1-J), S(1+J)]; ratio 3.0 covers up to ~50% jitter while
// staying well below the spread of organic traffic.
const beaconBandRatio = 3.0

// intervalBandRatio returns max/min of the inter-arrival intervals (a tight band
// => regular contact even when the per-interval jitter is high). Returns a large
// value when it can't be measured, so callers treat it as "not banded".
func intervalBandRatio(times []time.Time) float64 {
	if len(times) < 3 {
		return 1e9
	}
	min, max := 1e18, 0.0
	for i := 1; i < len(times); i++ {
		iv := times[i].Sub(times[i-1]).Seconds()
		if iv <= 0 {
			return 1e9 // out-of-order / duplicate timestamp
		}
		if iv < min {
			min = iv
		}
		if iv > max {
			max = iv
		}
	}
	if min <= 0 {
		return 1e9
	}
	return max / min
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// intervalRegularity returns the mean inter-arrival interval and the jitter
// (stddev/mean as a percent) over a series of timestamps. ok is false when
// there are too few samples or the mean is non-positive.
func intervalRegularity(times []time.Time) (mean time.Duration, jitterPct int, ok bool) {
	if len(times) < 3 {
		return 0, 0, false
	}
	ivs := make([]float64, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		ivs = append(ivs, times[i].Sub(times[i-1]).Seconds())
	}
	var sum float64
	for _, v := range ivs {
		sum += v
	}
	m := sum / float64(len(ivs))
	if m <= 0 {
		return 0, 0, false
	}
	var varSum float64
	for _, v := range ivs {
		d := v - m
		varSum += d * d
	}
	std := math.Sqrt(varSum / float64(len(ivs)))
	return time.Duration(m * float64(time.Second)), int(std / m * 100), true
}

// checkPathEnum detects HTTP content discovery: DistinctPaths distinct URL
// paths from one source within the window. Called with c.mu held.
func (c *Correlator) checkPathEnum(ev *event.Event, now time.Time) *event.Event {
	path := httpEventPath(ev)
	if path == "" {
		return nil
	}
	cfg := c.cfg.PathEnum
	st, ok := c.pathEnum[ev.Source.IP]
	if !ok || now.Sub(st.since) > cfg.Window {
		st = &setState{since: now, set: map[string]struct{}{}}
		c.pathEnum[ev.Source.IP] = st
	}
	if len(st.set) < corrSetCap {
		st.set[path] = struct{}{}
	}
	if len(st.set) < cfg.DistinctPaths {
		return nil
	}
	if !c.shouldEmit("pathenum|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:path_enumeration",
		Severity: c.pathSev,
		Source:   ev.Source,
		Dest:     event.Endpoint{Port: ev.Dest.Port},
		Proto:    ev.Proto,
		Handler:  ev.Handler,
		Meta: map[string]any{
			"distinct_paths": len(st.set),
			"window_s":       int(cfg.Window.Seconds()),
		},
	}
}

// checkDNSEnum detects DNS name enumeration: DistinctNames distinct query
// names from one source within the window (subdomain brute / NXDOMAIN flood
// / DGA churn). Called with c.mu held.
func (c *Correlator) checkDNSEnum(ev *event.Event, now time.Time) *event.Event {
	if ev.Handler != "dns" {
		return nil
	}
	name, _ := ev.Meta["qname"].(string)
	if name == "" {
		return nil
	}
	cfg := c.cfg.DNSEnum
	st, ok := c.dnsEnum[ev.Source.IP]
	if !ok || now.Sub(st.since) > cfg.Window {
		st = &setState{since: now, set: map[string]struct{}{}}
		c.dnsEnum[ev.Source.IP] = st
	}
	if len(st.set) < corrSetCap {
		st.set[name] = struct{}{}
	}
	if len(st.set) < cfg.DistinctNames {
		return nil
	}
	if !c.shouldEmit("dnsenum|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:dns_enumeration",
		Severity: c.dnsSev,
		Source:   ev.Source,
		Dest:     event.Endpoint{Port: ev.Dest.Port},
		Proto:    ev.Proto,
		Handler:  ev.Handler,
		Meta: map[string]any{
			"distinct_names": len(st.set),
			"window_s":       int(cfg.Window.Seconds()),
		},
	}
}

// httpEventPath extracts the request path from an HTTP-shaped event's meta,
// preferring an explicit http_path, else parsing the request line.
func httpEventPath(ev *event.Event) string {
	if p, ok := ev.Meta["http_path"].(string); ok && p != "" {
		return p
	}
	if rl, ok := ev.Meta["request_line"].(string); ok && rl != "" {
		f := strings.Fields(rl)
		if len(f) >= 2 {
			p := f[1]
			if i := strings.IndexByte(p, '?'); i >= 0 {
				p = p[:i]
			}
			return p
		}
	}
	return ""
}

func (c *Correlator) checkScan(ev *event.Event, now time.Time) *event.Event {
	cfg := c.cfg.PortScan
	st, ok := c.scan[ev.Source.IP]
	if !ok || now.Sub(st.since) > cfg.Window {
		st = &scanState{since: now, ports: map[int]struct{}{}}
		c.scan[ev.Source.IP] = st
	}
	st.ports[ev.Dest.Port] = struct{}{}
	if len(st.ports) < cfg.DistinctPorts {
		return nil
	}
	if !c.shouldEmit("scan|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	ports := make([]int, 0, len(st.ports))
	for p := range st.ports {
		ports = append(ports, p)
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:port_scan",
		Severity: c.scanSev,
		Source:   ev.Source,
		Proto:    "tcp",
		Meta: map[string]any{
			"distinct_ports": len(ports),
			"window_s":       int(cfg.Window.Seconds()),
			"ports":          ports,
		},
	}
}

// checkSweep detects an ICMP ping sweep: one source touching
// DistinctIPs distinct destination IPs via ICMP within Window. The
// destination IP comes from ev.Dest.IP (the honeynet host the ICMP
// responder answered for). Called with c.mu held.
func (c *Correlator) checkSweep(ev *event.Event, now time.Time) *event.Event {
	cfg := c.cfg.ICMPSweep
	dst := ev.Dest.IP
	if dst == "" {
		// Some ICMP events carry the touched IP in meta instead.
		if m, ok := ev.Meta["target_ip"].(string); ok {
			dst = m
		}
	}
	if dst == "" {
		return nil
	}
	st, ok := c.sweep[ev.Source.IP]
	if !ok || now.Sub(st.since) > cfg.Window {
		st = &sweepState{since: now, ips: map[string]struct{}{}}
		c.sweep[ev.Source.IP] = st
	}
	st.ips[dst] = struct{}{}
	if len(st.ips) < cfg.DistinctIPs {
		return nil
	}
	if !c.shouldEmit("sweep|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	ips := make([]string, 0, len(st.ips))
	for ip := range st.ips {
		ips = append(ips, ip)
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:icmp_sweep",
		Severity: c.sweepSev,
		Source:   ev.Source,
		Proto:    "icmp",
		Meta: map[string]any{
			"distinct_ips": len(ips),
			"window_s":     int(cfg.Window.Seconds()),
			"targets":      ips,
		},
	}
}

func (c *Correlator) checkBrute(ev *event.Event, now time.Time) *event.Event {
	cfg := c.cfg.BruteForce
	key := ev.Source.IP
	if cfg.PerPort {
		key += ":" + strconv.Itoa(ev.Dest.Port)
	}
	st, ok := c.brute[key]
	if !ok || now.Sub(st.since) > cfg.Window {
		st = &bruteState{since: now, creds: map[string]struct{}{}}
		c.brute[key] = st
	}
	st.count++
	if pair := extractCreds(ev); pair != "" {
		if len(st.creds) < 50 {
			st.creds[pair] = struct{}{}
		}
	}
	if st.count < cfg.Attempts {
		return nil
	}
	if !c.shouldEmit("brute|"+key, cfg.Window) {
		return nil
	}
	credList := make([]string, 0, len(st.creds))
	for k := range st.creds {
		credList = append(credList, k)
	}
	meta := map[string]any{
		"attempts":     st.count,
		"window_s":     int(cfg.Window.Seconds()),
		"unique_creds": len(credList),
	}
	if len(credList) > 0 {
		meta["credentials"] = credList
	}
	if cfg.PerPort {
		meta["port"] = ev.Dest.Port
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:brute_force",
		Severity: c.bruteSev,
		Source:   ev.Source,
		Dest:     ev.Dest,
		Proto:    ev.Proto,
		Meta:     meta,
	}
}

// checkSpray detects password spraying: one source trying many DISTINCT
// usernames within the window (the breadth signal, vs brute force's depth).
func (c *Correlator) checkSpray(ev *event.Event, now time.Time) *event.Event {
	cfg := c.cfg.PasswordSpray
	user := extractUser(ev)
	if user == "" {
		return nil
	}
	st, ok := c.spray[ev.Source.IP]
	if !ok || now.Sub(st.since) > cfg.Window {
		st = &sprayState{since: now, users: map[string]struct{}{}}
		c.spray[ev.Source.IP] = st
	}
	if len(st.users) < corrSetCap {
		st.users[user] = struct{}{}
	}
	if len(st.users) < cfg.DistinctUsers {
		return nil
	}
	if !c.shouldEmit("spray|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	users := make([]string, 0, len(st.users))
	for u := range st.users {
		users = append(users, u)
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:password_spray",
		Severity: c.spraySev,
		Source:   ev.Source,
		Dest:     ev.Dest,
		Proto:    ev.Proto,
		Meta: map[string]any{
			"distinct_users": len(users),
			"usernames":      users,
			"window_s":       int(cfg.Window.Seconds()),
		},
	}
}

// checkReuse detects the same credential pair attempted from many DISTINCT
// source IPs within the window — a shared credential list / botnet. The
// emitted event reports the username + source count but never the password.
func (c *Correlator) checkReuse(ev *event.Event, now time.Time) *event.Event {
	cfg := c.cfg.CredReuse
	cred := extractCreds(ev)
	if cred == "" || cred == ":" {
		return nil
	}
	st, ok := c.reuse[cred]
	if !ok || now.Sub(st.since) > cfg.Window {
		st = &reuseState{since: now, sources: map[string]struct{}{}}
		c.reuse[cred] = st
	}
	if len(st.sources) < corrSetCap {
		st.sources[ev.Source.IP] = struct{}{}
	}
	if len(st.sources) < cfg.DistinctSources {
		return nil
	}
	if !c.shouldEmit("reuse|"+cred, cfg.Window) {
		return nil
	}
	srcs := make([]string, 0, len(st.sources))
	for s := range st.sources {
		srcs = append(srcs, s)
	}
	user := cred
	if i := strings.IndexByte(cred, ':'); i >= 0 {
		user = cred[:i]
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:credential_reuse",
		Severity: c.reuseSev,
		Source:   ev.Source,
		Dest:     ev.Dest,
		Proto:    ev.Proto,
		Meta: map[string]any{
			"username":         user, // password deliberately omitted
			"distinct_sources": len(srcs),
			"sources":          srcs,
			"window_s":         int(cfg.Window.Seconds()),
		},
	}
}

// extractUser returns the username portion of the credential pair, or "".
func extractUser(ev *event.Event) string {
	cred := extractCreds(ev)
	if cred == "" {
		return ""
	}
	if i := strings.IndexByte(cred, ':'); i >= 0 {
		return cred[:i]
	}
	return cred
}

// checkSlowScan tracks port-touches over a long window (default 24h).
// Unlike port_scan, this state is NOT reset on each new event — it
// only ages out per-port entries older than the window so a one-port-
// per-hour scan accumulates over the day.
func (c *Correlator) checkSlowScan(ev *event.Event, now time.Time) *event.Event {
	cfg := c.cfg.SlowScan
	st, ok := c.slow[ev.Source.IP]
	if !ok {
		st = &slowState{firstSeen: now, ports: map[int]time.Time{}}
		c.slow[ev.Source.IP] = st
	}
	st.lastSeen = now
	if _, seen := st.ports[ev.Dest.Port]; !seen {
		st.ports[ev.Dest.Port] = now
	}
	// Age out old ports.
	cutoff := now.Add(-cfg.Window)
	for p, t := range st.ports {
		if t.Before(cutoff) {
			delete(st.ports, p)
		}
	}
	if len(st.ports) < cfg.DistinctPorts {
		return nil
	}
	if !c.shouldEmit("slow|"+ev.Source.IP, cfg.Window) {
		return nil
	}
	ports := make([]int, 0, len(st.ports))
	for p := range st.ports {
		ports = append(ports, p)
	}
	return &event.Event{
		ID:       event.NewID(),
		Time:     now,
		Sensor:   ev.Sensor,
		RuleID:   "correlate:slow_scan",
		Severity: c.slowSev,
		Source:   ev.Source,
		Proto:    "tcp",
		Meta: map[string]any{
			"distinct_ports": len(ports),
			"window_hours":   int(cfg.Window.Hours()),
			"first_seen":     st.firstSeen.Format(time.RFC3339),
			"last_seen":      st.lastSeen.Format(time.RFC3339),
			"ports":          ports,
			"spread_seconds": int(st.lastSeen.Sub(st.firstSeen).Seconds()),
		},
	}
}

// extractCreds pulls a credential pair out of well-known event meta keys.
// Returns "" when no credentials are present.
//
// Recognized meta layout:
//
//	ssh handlers don't capture passwords, but client_id is unique-ish
//	ftp -> user_line / pass_line
//	smtp_recv -> auth_user / auth_pass
//	mqtt -> username / password
//	ldap -> bind_dn / bind_pw
//	postgres -> startup_params[user] / password
//	mysql -> username / (auth_response_hex used as "the hashed password")
//	redis -> auth_password (no username)
//	vnc -> auth_response_hex (the DES-encrypted password)
//	winrm -> basic_user / basic_pass
func extractCreds(ev *event.Event) string {
	if ev.Meta == nil {
		return ""
	}
	get := func(k string) string {
		if v, ok := ev.Meta[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
		return ""
	}
	// User + pass pairs.
	pairs := [][2]string{
		{"auth_user", "auth_pass"},
		{"username", "password"},
		{"basic_user", "basic_pass"},
		{"bind_dn", "bind_pw"},
		{"user_line", "pass_line"},
	}
	for _, p := range pairs {
		u := get(p[0])
		pw := get(p[1])
		if u != "" || pw != "" {
			return u + ":" + pw
		}
	}
	// Postgres: startup_params has the user, password is a separate meta key.
	if pwd := get("password"); pwd != "" {
		if params, ok := ev.Meta["startup_params"].(map[string]string); ok {
			return params["user"] + ":" + pwd
		}
		return ":" + pwd
	}
	// MySQL: only the auth response is exposed (it's a hash).
	if u := get("username"); u != "" {
		if h := get("auth_response_hex"); h != "" {
			return u + ":hash=" + h
		}
	}
	// Redis: AUTH leaks just the password.
	if pwd := get("auth_password"); pwd != "" {
		return ":" + pwd
	}
	// VNC: auth response is opaque.
	if h := get("auth_response_hex"); h != "" {
		return ":hash=" + h
	}
	return ""
}

// shouldEmit collapses repeated aggregate events for the same key within
// the window so a sustained scan doesn't flood the sinks.
func (c *Correlator) shouldEmit(key string, window time.Duration) bool {
	now := time.Now()
	if t, ok := c.emitted[key]; ok && now.Sub(t) < window {
		return false
	}
	c.emitted[key] = now
	return true
}

// corrGCInterval throttles the idle-state sweep so it costs O(entries)
// at most once per interval rather than on every event.
const corrGCInterval = 5 * time.Minute

// gc evicts per-source state whose last activity is older than the
// relevant detector window, so the maps don't grow unbounded under many
// distinct/spoofed source IPs over a long-running sensor. Called with
// c.mu held.
func (c *Correlator) gc(now time.Time) {
	if !c.lastGC.IsZero() && now.Sub(c.lastGC) < corrGCInterval {
		return
	}
	c.lastGC = now
	for ip, st := range c.scan {
		if now.Sub(st.since) > effWindow(c.cfg.PortScan.Window, 30*time.Second) {
			delete(c.scan, ip)
		}
	}
	for k, st := range c.brute {
		if now.Sub(st.since) > effWindow(c.cfg.BruteForce.Window, time.Minute) {
			delete(c.brute, k)
		}
	}
	for ip, st := range c.slow {
		if now.Sub(st.lastSeen) > effWindow(c.cfg.SlowScan.Window, 24*time.Hour) {
			delete(c.slow, ip)
		}
	}
	for ip, st := range c.sweep {
		if now.Sub(st.since) > effWindow(c.cfg.ICMPSweep.Window, time.Minute) {
			delete(c.sweep, ip)
		}
	}
	for ip, st := range c.spray {
		if now.Sub(st.since) > effWindow(c.cfg.PasswordSpray.Window, 5*time.Minute) {
			delete(c.spray, ip)
		}
	}
	for k, st := range c.reuse {
		if now.Sub(st.since) > effWindow(c.cfg.CredReuse.Window, time.Hour) {
			delete(c.reuse, k)
		}
	}
	for ip, st := range c.pathEnum {
		if now.Sub(st.since) > effWindow(c.cfg.PathEnum.Window, time.Minute) {
			delete(c.pathEnum, ip)
		}
	}
	for ip, st := range c.dnsEnum {
		if now.Sub(st.since) > effWindow(c.cfg.DNSEnum.Window, time.Minute) {
			delete(c.dnsEnum, ip)
		}
	}
	for ip, st := range c.beacon {
		if len(st.times) == 0 || now.Sub(st.times[len(st.times)-1]) > effWindow(c.cfg.Beacon.Window, time.Hour) {
			delete(c.beacon, ip)
		}
	}
	for ip, st := range c.story {
		if now.Sub(st.lastSeen) > StoryWindow {
			delete(c.story, ip)
		}
	}
	// Additional opt-in correlator state: evict idle entries past each
	// detector's window so the maps don't grow unbounded.
	gcSet(c.hostSweep, now, effWindow(c.cfg.HostSweep.Window, time.Minute))
	ctWin := effWindow(c.cfg.CrossTarget.Window, time.Minute)
	for k, st := range c.crossTarget {
		if now.Sub(st.since) > ctWin {
			delete(c.crossTarget, k)
		}
	}
	gcSet(c.svcSweep, now, effWindow(c.cfg.ServiceSweep.Window, time.Minute))
	gcSet(c.uaRot, now, effWindow(c.cfg.UARotation.Window, 5*time.Minute))
	gcSet(c.exploit, now, effWindow(c.cfg.ExploitChain.Window, 10*time.Minute))
	gcSet(c.canary, now, effWindow(c.cfg.CanaryTrip.Window, time.Hour))
	gcSet(c.protoViol, now, effWindow(c.cfg.ProtocolViolation.Window, 5*time.Minute))
	gcSet(c.lateral, now, effWindow(c.cfg.LateralMovement.Window, 5*time.Minute))
	gcSet(c.otRecon, now, effWindow(c.cfg.OTRecon.Window, 5*time.Minute))
	for ip, st := range c.dataAcc {
		if now.Sub(st.since) > effWindow(c.cfg.DataAccess.Window, 5*time.Minute) {
			delete(c.dataAcc, ip)
		}
	}
	for ip, st := range c.malware {
		if now.Sub(st.since) > effWindow(c.cfg.MalwareCampaign.Window, 10*time.Minute) {
			delete(c.malware, ip)
		}
	}
	for ip, st := range c.webshell {
		if now.Sub(st.since) > effWindow(c.cfg.Webshell.Window, 10*time.Minute) {
			delete(c.webshell, ip)
		}
	}
	for k, st := range c.fpReuse {
		if now.Sub(st.since) > effWindow(c.cfg.FingerprintReuse.Window, time.Hour) {
			delete(c.fpReuse, k)
		}
	}
	for ip, st := range c.ics {
		if now.Sub(st.since) > effWindow(c.cfg.ICSControl.Window, 5*time.Minute) {
			delete(c.ics, ip)
		}
	}
	for ip, st := range c.flood {
		if now.Sub(st.since) > effWindow(c.cfg.SessionFlood.Window, time.Minute) {
			delete(c.flood, ip)
		}
	}
	for ip, st := range c.exfil {
		if now.Sub(st.since) > effWindow(c.cfg.Exfil.Window, 5*time.Minute) {
			delete(c.exfil, ip)
		}
	}
	for ip, st := range c.tiBurst {
		if now.Sub(st.since) > effWindow(c.cfg.ThreatIntelBurst.Window, 10*time.Minute) {
			delete(c.tiBurst, ip)
		}
	}
	gcSet(c.geoVel, now, effWindow(c.cfg.GeoVelocity.Window, time.Hour))
	gcSet(c.amp, now, effWindow(c.cfg.AmplificationProbe.Window, 5*time.Minute))
	gcSet(c.defCred, now, effWindow(c.cfg.DefaultCredSweep.Window, 5*time.Minute))
	for k, st := range c.cveCamp {
		if now.Sub(st.since) > effWindow(c.cfg.CVECampaign.Window, time.Hour) {
			delete(c.cveCamp, k)
		}
	}
	gcSet(c.toolRot, now, effWindow(c.cfg.ToolRotation.Window, time.Hour))
	for k, st := range c.destruct {
		if now.Sub(st.since) > effWindow(c.cfg.DestructiveAction.Window, 10*time.Minute) {
			delete(c.destruct, k)
		}
	}
	for k, st := range c.cloudCred {
		if now.Sub(st.since) > effWindow(c.cfg.CloudCredTheft.Window, 10*time.Minute) {
			delete(c.cloudCred, k)
		}
	}
	gcSet(c.ssrfCb, now, effWindow(c.cfg.SSRFCallback.Window, 10*time.Minute))
	for k, st := range c.mitmCap {
		if now.Sub(st.since) > effWindow(c.cfg.TLSMITMCapture.Window, 10*time.Minute) {
			delete(c.mitmCap, k)
		}
	}
	gcSet(c.fpRot, now, effWindow(c.cfg.FingerprintRotation.Window, 10*time.Minute))
	gcSet(c.ctrTake, now, effWindow(c.cfg.ContainerTakeover.Window, 10*time.Minute))
	gcSet(c.webProbe, now, effWindow(c.cfg.WebAttackProbe.Window, 10*time.Minute))
	gcSet(c.sshKey, now, effWindow(c.cfg.SSHKeySpray.Window, 10*time.Minute))
	for k, st := range c.spamRelay {
		if now.Sub(st.since) > effWindow(c.cfg.SpamRelay.Window, 10*time.Minute) {
			delete(c.spamRelay, k)
		}
	}
	for k, st := range c.dnsTunnel {
		if now.Sub(st.since) > effWindow(c.cfg.DNSTunnel.Window, 10*time.Minute) {
			delete(c.dnsTunnel, k)
		}
	}
	gcSet(c.reconExp, now, effWindow(c.cfg.ReconToExploit.Window, 30*time.Minute))
	for k, st := range c.honeytoken {
		if now.Sub(st.since) > effWindow(c.cfg.HoneytokenSpread.Window, time.Hour) {
			delete(c.honeytoken, k)
		}
	}
	gcSet(c.otKill, now, effWindow(c.cfg.OTKillChain.Window, 10*time.Minute))
	for k, st := range c.plcProg {
		if now.Sub(st.since) > effWindow(c.cfg.PLCProgramDownload.Window, 10*time.Minute) {
			delete(c.plcProg, k)
		}
	}
	for k, st := range c.modeChg {
		if now.Sub(st.since) > effWindow(c.cfg.ICSModeChange.Window, 10*time.Minute) {
			delete(c.modeChg, k)
		}
	}
	gcSet(c.remoteTool, now, effWindow(c.cfg.RemoteToolSweep.Window, 5*time.Minute))
	gcSet(c.oobMgmt, now, effWindow(c.cfg.OOBMgmtAccess.Window, 5*time.Minute))
	for k, st := range c.remoteExec {
		if now.Sub(st.since) > effWindow(c.cfg.RemoteExecCommand.Window, 10*time.Minute) {
			delete(c.remoteExec, k)
		}
	}
	gcSet(c.voipEnum, now, effWindow(c.cfg.VoIPEnum.Window, 5*time.Minute))
	for k, st := range c.tollFraud {
		if now.Sub(st.since) > effWindow(c.cfg.TollFraud.Window, 5*time.Minute) {
			delete(c.tollFraud, k)
		}
	}
	for k, st := range c.pbxCtrl {
		if now.Sub(st.since) > effWindow(c.cfg.PBXControl.Window, 10*time.Minute) {
			delete(c.pbxCtrl, k)
		}
	}
	for key, t := range c.emitted {
		if now.Sub(t) > 24*time.Hour {
			delete(c.emitted, key)
		}
	}
}

// gcSet evicts setState entries whose window has elapsed.
func gcSet(m map[string]*setState, now time.Time, window time.Duration) {
	for k, st := range m {
		if now.Sub(st.since) > window {
			delete(m, k)
		}
	}
}

func effWindow(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}
