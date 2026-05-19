package sink

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestSigv4Deterministic verifies the AWS Sigv4 implementation against a
// known example. We can't use the canonical AWS test vectors (those are
// for IAM / get-vault), but we can verify deterministic behavior: same
// inputs -> same signature, signature changes when inputs change.
func TestSigv4Deterministic(t *testing.T) {
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	body := []byte("Action=Publish&TopicArn=arn:aws:sns:us-east-1:123:t&Message=hi&Version=2010-03-31")
	r1, _ := http.NewRequest("POST", "https://sns.us-east-1.amazonaws.com/", strings.NewReader(string(body)))
	r1.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	r1.Header.Set("Host", "sns.us-east-1.amazonaws.com")
	signSigv4(r1, body, "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1", "sns", now)
	sig1 := r1.Header.Get("Authorization")

	r2, _ := http.NewRequest("POST", "https://sns.us-east-1.amazonaws.com/", strings.NewReader(string(body)))
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	r2.Header.Set("Host", "sns.us-east-1.amazonaws.com")
	signSigv4(r2, body, "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1", "sns", now)
	sig2 := r2.Header.Get("Authorization")

	if sig1 != sig2 {
		t.Fatalf("signature not deterministic:\n  %s\n  %s", sig1, sig2)
	}
	if !strings.Contains(sig1, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260519/us-east-1/sns/aws4_request") {
		t.Errorf("credential scope wrong: %s", sig1)
	}
	if !strings.Contains(sig1, "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date") {
		t.Errorf("signed headers wrong: %s", sig1)
	}
	if r1.Header.Get("X-Amz-Date") != "20260519T120000Z" {
		t.Errorf("x-amz-date wrong: %s", r1.Header.Get("X-Amz-Date"))
	}
}

func TestSigv4ChangesOnBody(t *testing.T) {
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	r1, _ := http.NewRequest("POST", "https://sns.us-east-1.amazonaws.com/", strings.NewReader("a=1"))
	r1.Header.Set("Host", "sns.us-east-1.amazonaws.com")
	signSigv4(r1, []byte("a=1"), "AK", "SK", "us-east-1", "sns", now)
	sig1 := r1.Header.Get("Authorization")

	r2, _ := http.NewRequest("POST", "https://sns.us-east-1.amazonaws.com/", strings.NewReader("a=2"))
	r2.Header.Set("Host", "sns.us-east-1.amazonaws.com")
	signSigv4(r2, []byte("a=2"), "AK", "SK", "us-east-1", "sns", now)
	sig2 := r2.Header.Get("Authorization")

	if sig1 == sig2 {
		t.Fatal("signatures should differ when body differs")
	}
}

func TestRegionFromARN(t *testing.T) {
	cases := map[string]string{
		"arn:aws:sns:us-east-1:123:t":     "us-east-1",
		"arn:aws:sns:eu-west-2:456:foo":   "eu-west-2",
		"":                                 "",
		"not-an-arn":                       "",
		"arn:aws:sns":                      "",
	}
	for in, want := range cases {
		if got := regionFromARN(in); got != want {
			t.Errorf("regionFromARN(%q) = %q; want %q", in, got, want)
		}
	}
}
