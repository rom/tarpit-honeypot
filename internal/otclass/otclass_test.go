package otclass

import "testing"

func TestClassification(t *testing.T) {
	cases := []struct {
		handler string
		class   Class
		target  string
	}{
		{"modbus", ICS, "ics-ot"},
		{"s7comm_plus", ICS, "ics-ot"},
		{"ethercat", ICS, "ics-ot"},
		{"synchrophasor", ICS, "ics-ot"},
		{"bacnet", BAS, "ics-ot"},
		{"knx", BAS, "ics-ot"},
		{"niagara_platform", BAS, "ics-ot"},
		{"obix", BAS, "ics-ot"},
		{"enocean", BAS, "ics-ot"},
		{"danfoss_aksm", BAS, "ics-ot"},
		{"hl7", MedTech, "healthcare"},
		{"dicom", MedTech, "healthcare"},
		{"fhir", MedTech, "healthcare"},
		{"astm", MedTech, "healthcare"},
		{"poct1", MedTech, "healthcare"},
		// Not OT.
		{"http", None, ""},
		{"ssh", None, ""},
		{"redis", None, ""},
		{"", None, ""},
	}
	for _, c := range cases {
		if got := Of(c.handler); got != c.class {
			t.Errorf("Of(%q) = %q, want %q", c.handler, got, c.class)
		}
		if got := IsOT(c.handler); got != (c.class != None) {
			t.Errorf("IsOT(%q) = %v, want %v", c.handler, got, c.class != None)
		}
		if got := Targeting(c.handler); got != c.target {
			t.Errorf("Targeting(%q) = %q, want %q", c.handler, got, c.target)
		}
	}
}
