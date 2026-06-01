package handler

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
)

// cloudMeta emulates a cloud instance metadata service (IMDS). After an SSRF
// or container escape, the first thing an attacker reaches for is
// 169.254.169.254 — the link-local metadata endpoint that hands out IAM
// credentials, user-data, and instance identity. We answer the AWS, GCP and
// Azure metadata layouts from one handler (they live on the same IP, different
// paths/headers) so a sensor placed behind a fake SSRF-able app, or bound to
// the link-local address, captures exactly which provider's credentials the
// attacker tried to steal.
//
// Any request that reaches the credential paths (IAM security-credentials,
// GCP service-account token, Azure identity/oauth2/token) is flagged — that
// is the credential-theft TTP, not benign metadata browsing. The returned
// credentials are obviously synthetic honeytokens; if they are ever *used*
// against your real cloud, the IOC fired.
type cloudMeta struct{}

func (c *cloudMeta) Name() string { return "cloud_metadata" }

func (c *cloudMeta) Handle(_ context.Context, conn net.Conn, cfg config.Listener) (Result, error) {
	withTimeout(conn, cfg.ReadTimeout)
	res := Result{Meta: map[string]any{}}
	br := bufio.NewReader(conn)
	capN := cfg.ReadBytes
	if capN <= 0 {
		capN = 8192
	}
	var buf bytes.Buffer
	for buf.Len() < capN {
		b, err := br.ReadByte()
		if err != nil {
			break
		}
		buf.WriteByte(b)
		if bytes.HasSuffix(buf.Bytes(), []byte("\r\n\r\n")) {
			break
		}
	}
	res.Payload = buf.Bytes()

	method, path := "", ""
	var metadataFlavor, aadToken, userAgent string
	for i, line := range strings.Split(buf.String(), "\r\n") {
		if i == 0 {
			res.Meta["request_line"] = line
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				method, path = strings.ToUpper(parts[0]), parts[1]
			}
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "metadata-flavor:"):
			metadataFlavor = strings.TrimSpace(line[16:])
		case strings.HasPrefix(lower, "metadata:"): // Azure sends "Metadata: true"
			res.Meta["azure_metadata_header"] = strings.TrimSpace(line[9:])
		case strings.HasPrefix(lower, "x-aws-ec2-metadata-token:"):
			aadToken = strings.TrimSpace(line[25:])
		case strings.HasPrefix(lower, "user-agent:"):
			userAgent = strings.TrimSpace(line[11:])
		}
	}
	res.Meta["method"] = method
	res.Meta["path"] = path
	if metadataFlavor != "" {
		res.Meta["metadata_flavor"] = metadataFlavor
	}
	if userAgent != "" {
		res.Meta["user_agent"] = userAgent
	}
	if aadToken != "" {
		res.Meta["imdsv2_token_present"] = true
	}

	provider, body, contentType, status := c.route(method, path, &res)
	res.Meta["cloud_provider"] = provider

	server := "EC2ws"
	switch provider {
	case "gcp":
		server = "Metadata Server for VM"
	case "azure":
		server = "IMDS/150.870.65.1551"
	}
	resp := "HTTP/1.1 " + status + "\r\n" +
		"Server: " + server + "\r\n" +
		"Content-Type: " + contentType + "\r\n" +
		"Content-Length: " + intToStr(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" +
		body
	if _, err := conn.Write([]byte(resp)); err != nil {
		res.Meta["write_err"] = err.Error()
	}
	res.BannerSent = "cloud_metadata " + provider + " " + status
	return res, nil
}

// route classifies the request by provider/path, flags credential theft, and
// returns the synthetic body to serve.
func (c *cloudMeta) route(method, path string, res *Result) (provider, body, contentType, status string) {
	contentType = "text/plain"
	status = "200 OK"
	low := strings.ToLower(path)

	switch {
	// --- AWS IMDS ---------------------------------------------------------
	case strings.HasPrefix(low, "/latest/api/token"):
		// IMDSv2 token request (PUT). Hand back an opaque token.
		provider = "aws"
		body = "AQAEAJ" + strings.Repeat("x", 50) + "=="
		return
	case strings.HasPrefix(low, "/latest/meta-data/iam/security-credentials"):
		provider = "aws"
		flagAnomaly(res, "cloud-credential-theft")
		// Listing vs fetching a specific role.
		if strings.HasSuffix(strings.TrimRight(low, "/"), "security-credentials") {
			body = "honeypot-instance-role"
		} else {
			contentType = "application/json"
			body = `{"Code":"Success","Type":"AWS-HMAC","AccessKeyId":"ASIAHONEYTOKEN0000","SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYHONEYTOKEN","Token":"FQoGZXIvYXdzEHONEYTOKEN","Expiration":"2099-01-01T00:00:00Z"}`
		}
		return
	case strings.HasPrefix(low, "/latest/meta-data/"):
		provider = "aws"
		switch {
		case strings.HasSuffix(low, "instance-id"):
			body = "i-0honeypot00000000"
		case strings.HasSuffix(low, "local-ipv4"):
			body = "10.0.0.42"
		case strings.HasSuffix(low, "iam/info"):
			contentType = "application/json"
			body = `{"Code":"Success","InstanceProfileArn":"arn:aws:iam::000000000000:instance-profile/honeypot-instance-role","InstanceProfileId":"AIPAHONEYTOKEN0000"}`
		default:
			body = "ami-id\ninstance-id\ninstance-type\nlocal-ipv4\niam/\nsecurity-groups"
		}
		return
	case strings.HasPrefix(low, "/latest/dynamic/instance-identity"):
		provider = "aws"
		contentType = "application/json"
		body = `{"accountId":"000000000000","region":"us-east-1","instanceId":"i-0honeypot00000000","instanceType":"t3.medium","imageId":"ami-honeypot"}`
		return

	// --- GCP metadata -----------------------------------------------------
	case strings.HasPrefix(low, "/computemetadata/v1/instance/service-accounts") &&
		strings.Contains(low, "token"):
		provider = "gcp"
		flagAnomaly(res, "cloud-credential-theft")
		contentType = "application/json"
		body = `{"access_token":"ya29.honeytoken_AAAAAAAAAAAAAAAAAAAAAAAA","expires_in":3599,"token_type":"Bearer"}`
		return
	case strings.HasPrefix(low, "/computemetadata/v1"):
		provider = "gcp"
		switch {
		case strings.HasSuffix(low, "/project/project-id"):
			body = "honeypot-project-000000"
		case strings.HasSuffix(low, "/instance/hostname"):
			body = "app-prod-01.c.honeypot-project-000000.internal"
		default:
			body = "instance/\nproject/"
		}
		return

	// --- Azure IMDS -------------------------------------------------------
	case strings.HasPrefix(low, "/metadata/identity/oauth2/token"):
		provider = "azure"
		flagAnomaly(res, "cloud-credential-theft")
		contentType = "application/json"
		body = `{"access_token":"eyJ0eXAiOiJKV1QhoneytokenAAAA","client_id":"00000000-0000-0000-0000-000000000000","expires_in":"3599","resource":"https://management.azure.com/","token_type":"Bearer"}`
		return
	case strings.HasPrefix(low, "/metadata/instance"):
		provider = "azure"
		contentType = "application/json"
		body = `{"compute":{"location":"eastus","name":"app-prod-01","resourceGroupName":"honeypot-rg","subscriptionId":"00000000-0000-0000-0000-000000000000","vmId":"00000000-0000-0000-0000-000000000000"},"network":{"interface":[{"ipv4":{"ipAddress":[{"privateIpAddress":"10.0.0.42"}]}}]}}`
		return
	}

	provider = "unknown"
	status = "404 Not Found"
	body = "not found"
	return
}
