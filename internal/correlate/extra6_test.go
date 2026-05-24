package correlate

import (
	"testing"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
)

func TestPLCProgramDownloadFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		PLCProgramDownload: config.CorrPLCProgramDownload{Enabled: true, Events: 1, Window: time.Minute, Severity: "critical"},
	})
	ev := mkEvent("10.0.0.5", 9600, time.Now().UTC())
	ev.Handler = "fins_tcp"
	ev.Anomalies = []string{"fins-program-download"}
	if aggregate(cor.Observe(ev), "correlate:plc_program_download") == nil {
		t.Fatal("plc_program_download did not fire")
	}
	// A plain read must not trip it.
	ev2 := mkEvent("10.0.0.6", 9600, time.Now().UTC())
	ev2.Handler = "fins_tcp"
	ev2.Anomalies = []string{"fins-tcp-probe"}
	if aggregate(cor.Observe(ev2), "correlate:plc_program_download") != nil {
		t.Error("a probe should not trip plc_program_download")
	}
}

func TestICSModeChangeFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		ICSModeChange: config.CorrICSModeChange{Enabled: true, Events: 1, Window: time.Minute, Severity: "critical"},
	})
	ev := mkEvent("10.0.0.7", 20256, time.Now().UTC())
	ev.Handler = "pcom"
	ev.Anomalies = []string{"pcom-mode-change"}
	if aggregate(cor.Observe(ev), "correlate:ics_mode_change") == nil {
		t.Fatal("ics_mode_change did not fire")
	}
}

func TestOTKillChainFires(t *testing.T) {
	cor, _ := New(config.Correlate{
		OTKillChain: config.CorrOTKillChain{Enabled: true, Window: time.Minute, Severity: "critical"},
	})
	now := time.Now().UTC()
	// First a recon touch on an ICS protocol (no control yet).
	ev1 := mkEvent("10.0.0.9", 502, now)
	ev1.Handler = "modbus"
	if aggregate(cor.Observe(ev1), "correlate:ot_kill_chain") != nil {
		t.Error("recon alone should not fire ot_kill_chain")
	}
	// Then a control command from the same source -> fire.
	ev2 := mkEvent("10.0.0.9", 502, now.Add(time.Second))
	ev2.Handler = "modbus"
	ev2.Anomalies = []string{"modbus-write-attempt"}
	if aggregate(cor.Observe(ev2), "correlate:ot_kill_chain") == nil {
		t.Fatal("ot_kill_chain did not fire after recon + control")
	}
}
