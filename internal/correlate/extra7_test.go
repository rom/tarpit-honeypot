package correlate

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

func TestRemoteToolSweepFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		RemoteToolSweep: config.CorrRemoteToolSweep{Enabled: true, DistinctTools: 3, Window: time.Minute, Severity: "high"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i, h := range []string{"teamviewer", "radmin", "pcanywhere"} {
		ev := mkEvent("1.2.3.4", 5631+i, now.Add(time.Duration(i)*time.Second))
		ev.Handler = h
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:remote_tool_sweep") == nil {
		t.Fatalf("remote_tool_sweep did not fire: %v", last)
	}
	// An OS-native lateral service must not contribute.
	ev := mkEvent("5.5.5.5", 3389, now)
	ev.Handler = "rdp"
	if aggregate(cor.Observe(ev), "correlate:remote_tool_sweep") != nil {
		t.Error("rdp should not trip remote_tool_sweep")
	}
}

func TestOOBMgmtAccessFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		OOBMgmtAccess: config.CorrOOBMgmtAccess{Enabled: true, DistinctServices: 3, Window: time.Minute, Severity: "high"},
	})
	now := time.Now().UTC()
	var last []*event.Event
	for i, h := range []string{"redfish", "ipmi", "lantronix"} {
		ev := mkEvent("9.9.9.9", 623+i, now.Add(time.Duration(i)*time.Second))
		ev.Handler = h
		last = cor.Observe(ev)
	}
	if aggregate(last, "correlate:oob_mgmt_access") == nil {
		t.Fatalf("oob_mgmt_access did not fire: %v", last)
	}
}

func TestRemoteExecCommandFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		RemoteExecCommand: config.CorrRemoteExecCommand{Enabled: true, Events: 1, Window: time.Minute, Severity: "critical"},
	})
	ev := mkEvent("10.0.0.5", 512, time.Now().UTC())
	ev.Handler = "rexec"
	ev.Anomalies = []string{"rexec-command"}
	if aggregate(cor.Observe(ev), "correlate:remote_exec_command") == nil {
		t.Fatal("remote_exec_command did not fire")
	}
}
