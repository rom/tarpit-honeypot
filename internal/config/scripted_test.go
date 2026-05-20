package config

import "testing"

func TestScriptedProtoValidate(t *testing.T) {
	ok := ScriptedProto{
		Greeting: "hi\\r\\n",
		Rules: []ScriptedRule{
			{Match: "prefix", Value: "GET", Respond: "ok\\r\\n"},
			{Match: "regex", Value: "^a+$", RespondHex: "6f6b"},
			{Match: "hex_prefix", Value: "deadbeef", Close: true},
			{Match: "contains", Value: "secret", Anomaly: "x"},
			{Match: "any", Respond: "x"},
		},
		Default: "err\\r\\n",
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}

	bad := map[string]ScriptedProto{
		"empty":            {},
		"bad mode":         {Greeting: "x", Rules: []ScriptedRule{{Match: "nope", Value: "a"}}},
		"bad regex":        {Greeting: "x", Rules: []ScriptedRule{{Match: "regex", Value: "("}}},
		"bad hex":          {Greeting: "x", Rules: []ScriptedRule{{Match: "hex_prefix", Value: "zz"}}},
		"missing value":    {Greeting: "x", Rules: []ScriptedRule{{Match: "prefix"}}},
		"both greet forms": {Greeting: "a", GreetingHex: "6161"},
		"rounds too big":   {Greeting: "x", MaxRounds: 999},
		"bad escape":       {Greeting: "x\\q"},
		"both resp forms":  {Greeting: "x", Rules: []ScriptedRule{{Match: "any", Respond: "a", RespondHex: "61"}}},
	}
	for name, b := range bad {
		if err := b.Validate(); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

func TestDecodeScriptedField(t *testing.T) {
	cases := []struct {
		text, hex string
		want      string
	}{
		{"plain", "", "plain"},
		{"a\\r\\nb", "", "a\r\nb"},
		{"\\x41\\x42", "", "AB"},
		{"tab\\there", "", "tab\there"},
		{"", "48656c6c6f", "Hello"},
	}
	for _, c := range cases {
		got, err := DecodeScriptedField(c.text, c.hex)
		if err != nil {
			t.Errorf("DecodeScriptedField(%q,%q) error: %v", c.text, c.hex, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("DecodeScriptedField(%q,%q) = %q; want %q", c.text, c.hex, got, c.want)
		}
	}
}
