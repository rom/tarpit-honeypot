package handler

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/config"
	"github.com/rom/tarpit-honeypot/internal/identity"
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
type cloudMeta struct {
	id *identity.Identity
}

func (c *cloudMeta) Name() string { return "cloud_metadata" }

// cloudCreds holds the per-deployment synthetic credentials cloud_metadata
// serves. Each value is deterministic for a deployment (derived from the
// deployment seed) but unique across deployments, so two sensors never hand
// out the same fake key — and, like the webapp honeytokens, a served secret
// can be registered and alerted on if it ever appears in real cloud auth logs.
type cloudCreds struct {
	awsAccessKeyID string // "ASIA..." STS temp key id (20 chars)
	awsSecret      string // 40-char secret-access-key shape
	awsToken       string // long opaque session token
	awsAccountID   string // 12-digit account id
	awsInstanceID  string // "i-<17 hex>"
	awsRoleName    string
	awsAMI         string // "ami-<17 hex>"
	gcpToken       string // "ya29...." access token
	gcpProjectID   string // "<name>-<6 digits>"
	azureToken     string // JWT-shaped bearer
	azureClientID  string // GUID
	azureSubID     string // GUID
	azureVMID      string // GUID
	azureRG        string
}

// deriveCloudCreds builds the per-deployment credential set. Reuses the shared
// idBytes/encodeAlpha helpers (see vulnweb.go) so the values match the
// established honeytoken style and degrade gracefully when no identity is set.
func deriveCloudCreds(id *identity.Identity) cloudCreds {
	digits := func(label string, n int) string { return encodeAlpha(idBytes(id, label, n), "0123456789") }
	hexs := func(label string, n int) string { return encodeAlpha(idBytes(id, label, n), "0123456789abcdef") }
	return cloudCreds{
		awsAccessKeyID: "ASIA" + encodeAlpha(idBytes(id, "cloud-aws-id", 16), honeyAWSAlpha),
		awsSecret:      encodeAlpha(idBytes(id, "cloud-aws-secret", 40), honeyB64Alpha),
		awsToken:       "FQoGZXIvYXdzE" + encodeAlpha(idBytes(id, "cloud-aws-token", 80), honeyB64Alpha),
		awsAccountID:   digits("cloud-aws-acct", 12),
		awsInstanceID:  "i-0" + hexs("cloud-aws-inst", 16),
		awsRoleName:    "app-prod-ec2-role",
		awsAMI:         "ami-0" + hexs("cloud-aws-ami", 16),
		gcpToken:       "ya29.c." + encodeAlpha(idBytes(id, "cloud-gcp-token", 90), honeyB64Alpha),
		gcpProjectID:   "prod-platform-" + digits("cloud-gcp-proj", 6),
		azureToken:     "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9." + encodeAlpha(idBytes(id, "cloud-az-tok", 64), honeyB64Alpha),
		azureClientID:  guidFrom(idBytes(id, "cloud-az-client", 16)),
		azureSubID:     guidFrom(idBytes(id, "cloud-az-sub", 16)),
		azureVMID:      guidFrom(idBytes(id, "cloud-az-vm", 16)),
		azureRG:        "rg-platform-prod",
	}
}

// guidFrom renders 16 bytes as a canonical 8-4-4-4-12 hex GUID.
func guidFrom(b []byte) string {
	var x [16]byte
	copy(x[:], b)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		x[0:4], x[4:6], x[6:8], x[8:10], x[10:16])
}

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

	provider, body, contentType, status := c.route(method, path, deriveCloudCreds(c.id), &res)
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
// returns the synthetic body to serve. cr supplies the per-deployment fake
// credentials so two sensors never serve identical keys.
func (c *cloudMeta) route(method, path string, cr cloudCreds, res *Result) (provider, body, contentType, status string) {
	contentType = "text/plain"
	status = "200 OK"
	low := strings.ToLower(path)

	switch {
	// --- AWS IMDS ---------------------------------------------------------
	case strings.HasPrefix(low, "/latest/api/token"):
		// IMDSv2 token request (PUT). Hand back an opaque token.
		provider = "aws"
		body = "AQAEA" + encodeAlpha(idBytes(c.id, "cloud-imdsv2", 48), honeyB64Alpha) + "=="
		return
	case strings.HasPrefix(low, "/latest/meta-data/iam/security-credentials"):
		provider = "aws"
		flagAnomaly(res, "cloud-credential-theft")
		// Listing vs fetching a specific role.
		if strings.HasSuffix(strings.TrimRight(low, "/"), "security-credentials") {
			body = cr.awsRoleName
		} else {
			contentType = "application/json"
			body = fmt.Sprintf(`{"Code":"Success","Type":"AWS-HMAC","AccessKeyId":%q,"SecretAccessKey":%q,"Token":%q,"Expiration":"2099-01-01T00:00:00Z"}`,
				cr.awsAccessKeyID, cr.awsSecret, cr.awsToken)
		}
		return
	case strings.HasPrefix(low, "/latest/meta-data/"):
		provider = "aws"
		switch {
		case strings.HasSuffix(low, "instance-id"):
			body = cr.awsInstanceID
		case strings.HasSuffix(low, "local-ipv4"):
			body = "10.0.0.42"
		case strings.HasSuffix(low, "iam/info"):
			contentType = "application/json"
			body = fmt.Sprintf(`{"Code":"Success","InstanceProfileArn":"arn:aws:iam::%s:instance-profile/%s","InstanceProfileId":"AIPA%s"}`,
				cr.awsAccountID, cr.awsRoleName, encodeAlpha(idBytes(c.id, "cloud-aws-profid", 17), honeyAWSAlpha))
		default:
			body = "ami-id\ninstance-id\ninstance-type\nlocal-ipv4\niam/\nsecurity-groups"
		}
		return
	case strings.HasPrefix(low, "/latest/dynamic/instance-identity"):
		provider = "aws"
		contentType = "application/json"
		body = fmt.Sprintf(`{"accountId":%q,"region":"us-east-1","instanceId":%q,"instanceType":"t3.medium","imageId":%q}`,
			cr.awsAccountID, cr.awsInstanceID, cr.awsAMI)
		return

	// --- GCP metadata -----------------------------------------------------
	case strings.HasPrefix(low, "/computemetadata/v1/instance/service-accounts") &&
		strings.Contains(low, "token"):
		provider = "gcp"
		flagAnomaly(res, "cloud-credential-theft")
		contentType = "application/json"
		body = fmt.Sprintf(`{"access_token":%q,"expires_in":3599,"token_type":"Bearer"}`, cr.gcpToken)
		return
	case strings.HasPrefix(low, "/computemetadata/v1"):
		provider = "gcp"
		switch {
		case strings.HasSuffix(low, "/project/project-id"):
			body = cr.gcpProjectID
		case strings.HasSuffix(low, "/instance/hostname"):
			body = "app-prod-01.c." + cr.gcpProjectID + ".internal"
		default:
			body = "instance/\nproject/"
		}
		return

	// --- Azure IMDS -------------------------------------------------------
	case strings.HasPrefix(low, "/metadata/identity/oauth2/token"):
		provider = "azure"
		flagAnomaly(res, "cloud-credential-theft")
		contentType = "application/json"
		body = fmt.Sprintf(`{"access_token":%q,"client_id":%q,"expires_in":"3599","resource":"https://management.azure.com/","token_type":"Bearer"}`,
			cr.azureToken, cr.azureClientID)
		return
	case strings.HasPrefix(low, "/metadata/instance"):
		provider = "azure"
		contentType = "application/json"
		body = fmt.Sprintf(`{"compute":{"location":"eastus","name":"app-prod-01","resourceGroupName":%q,"subscriptionId":%q,"vmId":%q},"network":{"interface":[{"ipv4":{"ipAddress":[{"privateIpAddress":"10.0.0.42"}]}}]}}`,
			cr.azureRG, cr.azureSubID, cr.azureVMID)
		return
	}

	provider = "unknown"
	status = "404 Not Found"
	body = "not found"
	return
}
