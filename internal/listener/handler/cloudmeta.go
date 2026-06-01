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
			body = "app-prod-ec2-role"
		} else {
			contentType = "application/json"
			body = `{"Code":"Success","Type":"AWS-HMAC","AccessKeyId":"ASIA4XTPZ9QK7M2BNVRD","SecretAccessKey":"hT3kVq9mZ1cR8wPnLs6yEfBd2uXgKaQj7N0iMvCt","Token":"FQoGZXIvYXdzEBYaDPq7m2nVrK9wL3sJ4xT8cN1pBdRfGhUaKmZ","Expiration":"2099-01-01T00:00:00Z"}`
		}
		return
	case strings.HasPrefix(low, "/latest/meta-data/"):
		provider = "aws"
		switch {
		case strings.HasSuffix(low, "instance-id"):
			body = "i-0a1b2c3d4e5f60718"
		case strings.HasSuffix(low, "local-ipv4"):
			body = "10.0.0.42"
		case strings.HasSuffix(low, "iam/info"):
			contentType = "application/json"
			body = `{"Code":"Success","InstanceProfileArn":"arn:aws:iam::481516234299:instance-profile/app-prod-ec2-role","InstanceProfileId":"AIPA4XTPZ9QK7M2BNVRDX"}`
		default:
			body = "ami-id\ninstance-id\ninstance-type\nlocal-ipv4\niam/\nsecurity-groups"
		}
		return
	case strings.HasPrefix(low, "/latest/dynamic/instance-identity"):
		provider = "aws"
		contentType = "application/json"
		body = `{"accountId":"481516234299","region":"us-east-1","instanceId":"i-0a1b2c3d4e5f60718","instanceType":"t3.medium","imageId":"ami-0c7217cdde317cfec"}`
		return

	// --- GCP metadata -----------------------------------------------------
	case strings.HasPrefix(low, "/computemetadata/v1/instance/service-accounts") &&
		strings.Contains(low, "token"):
		provider = "gcp"
		flagAnomaly(res, "cloud-credential-theft")
		contentType = "application/json"
		body = `{"access_token":"ya29.c.b0Aaekm1L4xR9tZ7qPvN3sKdWfYgHj2mUcBnXa5oQpErTiLsMv8wDgFhJk","expires_in":3599,"token_type":"Bearer"}`
		return
	case strings.HasPrefix(low, "/computemetadata/v1"):
		provider = "gcp"
		switch {
		case strings.HasSuffix(low, "/project/project-id"):
			body = "prod-platform-204815"
		case strings.HasSuffix(low, "/instance/hostname"):
			body = "app-prod-01.c.prod-platform-204815.internal"
		default:
			body = "instance/\nproject/"
		}
		return

	// --- Azure IMDS -------------------------------------------------------
	case strings.HasPrefix(low, "/metadata/identity/oauth2/token"):
		provider = "azure"
		flagAnomaly(res, "cloud-credential-theft")
		contentType = "application/json"
		body = `{"access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5xZGw5In0.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyJ9.Qx7Lp2mVrK9wN3sJ4xT8cN1pBdRfGhUaKmZ","client_id":"7c4e1f08-3a92-4d6b-b15e-2f9081a6c3d4","expires_in":"3599","resource":"https://management.azure.com/","token_type":"Bearer"}`
		return
	case strings.HasPrefix(low, "/metadata/instance"):
		provider = "azure"
		contentType = "application/json"
		body = `{"compute":{"location":"eastus","name":"app-prod-01","resourceGroupName":"rg-platform-prod","subscriptionId":"7c4e1f08-3a92-4d6b-b15e-2f9081a6c3d4","vmId":"a3f1c8b2-9d4e-4f6a-8c1d-2b5e7f9081a6"},"network":{"interface":[{"ipv4":{"ipAddress":[{"privateIpAddress":"10.0.0.42"}]}}]}}`
		return
	}

	provider = "unknown"
	status = "404 Not Found"
	body = "not found"
	return
}
