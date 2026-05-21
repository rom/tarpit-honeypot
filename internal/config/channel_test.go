package config

import "testing"

func boolp(b bool) *bool { return &b }

func TestChannelOnDefault(t *testing.T) {
	if !(Channel{}).On() {
		t.Error("a channel with no enabled field must default to on")
	}
	if !(Channel{Enabled: boolp(true)}).On() {
		t.Error("enabled:true must be on")
	}
	if (Channel{Enabled: boolp(false)}).On() {
		t.Error("enabled:false must be off")
	}
}

// A disabled channel ships half-configured: it must not be type-validated
// (so an outbound sink without its secret/endpoint still loads), but its id
// is kept so routes referencing it still validate.
func TestDisabledChannelSkipsValidation(t *testing.T) {
	c := &Config{
		Sensor: Sensor{DataDir: "/tmp/x"},
		Channels: []Channel{
			{ID: "console", Type: "stdout"},
			{ID: "hook", Type: "webhook", Enabled: boolp(false)}, // no URL — would fail if validated
		},
		Routes: []Route{{Channels: []string{"hook"}}}, // route to the disabled channel
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		t.Errorf("disabled webhook (no url) + route to it should validate: %v", err)
	}
}

func TestEnabledChannelStillValidated(t *testing.T) {
	c := &Config{
		Sensor:   Sensor{DataDir: "/tmp/x"},
		Channels: []Channel{{ID: "hook", Type: "webhook"}}, // enabled, no URL
	}
	c.applyDefaults()
	if err := c.Validate(); err == nil {
		t.Error("an enabled webhook with no url must still fail validation")
	}
}
