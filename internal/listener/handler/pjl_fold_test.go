package handler

import "testing"

// Regression for the fuzz-found panic: strings.ToUpper is not length-preserving
// (e.g. 'ȿ' U+023F → 'Ȿ' U+2C7E grows 2→3 bytes), so indexing a ToUpper copy and
// slicing the original could run past the end. These inputs panicked before the
// asciiIndexFold fix.
func TestPJLArgParsersNoPanicOnGrowingRunes(t *testing.T) {
	// 'ȿ' before the keyword is the minimal trigger; include a few shapes.
	cases := []string{
		"ȿname=", "ȿNAME=", "ȿname=\"x\"", "ȿpassword=secret", "ȿfoo=bar",
		"ȿȿȿname=", "@PJL FSQUERY ȿname=/etc/passwd",
	}
	for _, in := range cases {
		_ = pjlNameArg(in)       // must not panic
		_ = pjlPasswordValue(in) // must not panic
		_ = pjlValueOf(in, "foo")
		_ = pjlFSQuery(in)
		_ = pjlFSUpload(in)
	}

	// Correct extraction is preserved (ASCII-fold match, original-case value).
	if got := pjlNameArg(`@PJL FSQUERY NAME="/etc/passwd"`); got != "/etc/passwd" {
		t.Errorf(`pjlNameArg = %q; want "/etc/passwd"`, got)
	}
	if got := pjlNameArg("name=Foo.TXT"); got != "Foo.TXT" {
		t.Errorf("pjlNameArg case-preserve = %q; want Foo.TXT", got)
	}
	if got := pjlPasswordValue("@PJL DEFAULT PASSWORD = hunter2"); got != "hunter2" {
		t.Errorf("pjlPasswordValue = %q; want hunter2", got)
	}
	if got := pjlValueOf("SIZE=2048 FOO", "SIZE"); got != "2048" {
		t.Errorf("pjlValueOf = %q; want 2048", got)
	}
}

// The same ToLower-copy-index bug class appeared in the XML/JS extractors.
// 'Ⱥ' U+023A → 'ⱥ' U+2C65 grows 2→3 bytes under ToLower; a growing rune before
// the match made the lowercased copy longer than the original and overran a
// body[i:] slice. These inputs panicked before the asciiIndexFold fix.
func TestXMLJSExtractorsNoPanicOnGrowingRunes(t *testing.T) {
	grow := "Ⱥ"
	for _, b := range []string{
		grow + "<name>x</name>", grow + "<NAME>x", "<name>" + grow,
		grow + "<script>alert(1)</script>", grow + "javascript:x", "<script" + grow,
		grow + ":tag>v</tag>", "<tag>" + grow,
	} {
		_ = danfossXMLField(b, "name")
		_ = xmlTagValue(b, "tag")
		_ = extractJavaScript(b)
	}
	// Extraction still correct on well-formed input.
	if got := danfossXMLField("<Name>Bar</Name>", "name"); got != "Bar" {
		t.Errorf("danfossXMLField = %q; want Bar", got)
	}
	if got := xmlTagValue("<ns:Tag>Baz</ns:Tag>", "tag"); got != "Baz" {
		t.Errorf("xmlTagValue = %q; want Baz", got)
	}
	if js := extractJavaScript("<script>alert(1)</script>"); len(js) == 0 {
		t.Error("extractJavaScript returned nothing for a <script> body")
	}
}
