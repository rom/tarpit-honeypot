package sink

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/event"
)

// snsSink publishes an event to an AWS SNS topic using a hand-rolled
// minimal Sigv4 signer. Keeping the AWS SDK out of the dep tree saves
// ~60MB of binary footprint and avoids transitively dragging in a lot of
// AWS-internal code.
type snsSink struct {
	id        string
	topicARN  string
	region    string
	accessKey string
	secretKey string
	sessionTk string
	client    *http.Client
}

func newSNS(ch config.Channel) (Sink, error) {
	if ch.TopicARN == "" {
		return nil, fmt.Errorf("sns %s: topic_arn required", ch.ID)
	}
	region := ch.Region
	if region == "" {
		region = regionFromARN(ch.TopicARN)
	}
	if region == "" {
		return nil, fmt.Errorf("sns %s: region required (or include it in topic_arn)", ch.ID)
	}
	ak := os.Getenv(ch.AccessKeyEnv)
	sk := os.Getenv(ch.SecretKeyEnv)
	if ak == "" || sk == "" {
		return nil, fmt.Errorf("sns %s: access_key_env (%s) or secret_key_env (%s) empty",
			ch.ID, ch.AccessKeyEnv, ch.SecretKeyEnv)
	}
	st := ""
	if ch.SessionTokenEnv != "" {
		st = os.Getenv(ch.SessionTokenEnv)
	}
	return &snsSink{
		id:        ch.ID,
		topicARN:  ch.TopicARN,
		region:    region,
		accessKey: ak,
		secretKey: sk,
		sessionTk: st,
		client:    &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (s *snsSink) ID() string { return s.id }

func (s *snsSink) Send(ctx context.Context, ev *event.Event) error {
	subject := fmt.Sprintf("[%s] %s from %s", ev.Severity, ev.RuleID, ev.Source.IP)
	if len(subject) > 100 {
		subject = subject[:100]
	}
	msg := fmt.Sprintf("event %s\nsensor=%s\ntime=%s\nrule=%s\nsource=%s:%d\ndest=%s:%d\nseverity=%s",
		ev.ID, ev.Sensor, ev.Time.UTC().Format(time.RFC3339Nano),
		ev.RuleID, ev.Source.IP, ev.Source.Port, ev.Dest.IP, ev.Dest.Port, ev.Severity)

	form := url.Values{}
	form.Set("Action", "Publish")
	form.Set("Version", "2010-03-31")
	form.Set("TopicArn", s.topicARN)
	form.Set("Subject", subject)
	form.Set("Message", msg)
	body := form.Encode()

	host := fmt.Sprintf("sns.%s.amazonaws.com", s.region)
	endpoint := "https://" + host + "/"
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader([]byte(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Host", host)
	if s.sessionTk != "" {
		req.Header.Set("X-Amz-Security-Token", s.sessionTk)
	}
	signSigv4(req, []byte(body), s.accessKey, s.secretKey, s.region, "sns", time.Now().UTC())

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("sns: status %d: %s", resp.StatusCode, truncate(string(respBody), 300))
	}
	return nil
}

func (s *snsSink) Close() error { return nil }

func regionFromARN(arn string) string {
	// arn:aws:sns:us-east-1:123456789012:my-topic
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 || parts[0] != "arn" {
		return ""
	}
	return parts[3]
}

// signSigv4 implements just enough AWS Signature Version 4 for SNS POSTs.
// Reference: https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
func signSigv4(req *http.Request, body []byte, accessKey, secretKey, region, service string, now time.Time) {
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)

	payloadHash := sha256Hex(body)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	// Canonical headers: lowercased name + trimmed value, sorted by name.
	type kv struct{ k, v string }
	var headers []kv
	for k, vs := range req.Header {
		lk := strings.ToLower(k)
		// Only sign the small set Sigv4 requires; over-signing is fine but
		// keep it deterministic.
		if lk == "host" || lk == "content-type" || lk == "x-amz-date" ||
			lk == "x-amz-content-sha256" || lk == "x-amz-security-token" {
			headers = append(headers, kv{lk, strings.TrimSpace(strings.Join(vs, ","))})
		}
	}
	// Make sure Host is in the headers even if the http client sets it later.
	hasHost := false
	for _, h := range headers {
		if h.k == "host" {
			hasHost = true
			break
		}
	}
	if !hasHost {
		headers = append(headers, kv{"host", req.URL.Host})
	}
	sort.Slice(headers, func(i, j int) bool { return headers[i].k < headers[j].k })

	var canonHdrs strings.Builder
	var signedNames []string
	for _, h := range headers {
		canonHdrs.WriteString(h.k)
		canonHdrs.WriteString(":")
		canonHdrs.WriteString(h.v)
		canonHdrs.WriteString("\n")
		signedNames = append(signedNames, h.k)
	}
	signedHeaders := strings.Join(signedNames, ";")

	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalRequest := req.Method + "\n" +
		canonicalURI + "\n" +
		req.URL.RawQuery + "\n" +
		canonHdrs.String() + "\n" +
		signedHeaders + "\n" +
		payloadHash

	credScope := dateStamp + "/" + region + "/" + service + "/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + credScope + "\n" + sha256Hex([]byte(canonicalRequest))

	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	auth := "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + credScope +
		", SignedHeaders=" + signedHeaders +
		", Signature=" + signature
	req.Header.Set("Authorization", auth)
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}
