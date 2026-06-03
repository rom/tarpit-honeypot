package handler

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSVNGreetingAndRepoCapture(t *testing.T) {
	client, server := loopbackPair(t)
	// A realistic svnserve client response selecting v2 + capabilities and the
	// repo URL it wants to reach.
	if _, err := client.Write([]byte("( 2 ( edit-pipeline svndiff1 ) 25:svn://10.0.0.5/repo/trunk ) ")); err != nil {
		t.Fatal(err)
	}
	res, err := (&svn{}).Handle(context.Background(), server, smallSvcCfg())
	if err != nil {
		t.Fatal(err)
	}
	if res.BannerSent == "" {
		t.Error("svn handler should greet first")
	}
	url, _ := res.Meta["svn_repo_url"].(string)
	if !strings.HasPrefix(url, "svn://10.0.0.5/repo") {
		t.Errorf("svn_repo_url = %q; want the svn:// repo url", url)
	}
	if !hasAnomaly(res, "svn-repo-access") {
		t.Errorf("repo access not flagged: %v", res.Meta["anomalies"])
	}
	// The client greeting from the honeypot must look like svnserve.
	buf := make([]byte, 256)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := client.Read(buf)
	if !strings.Contains(string(buf[:n]), "( success ( 2 2") {
		t.Errorf("greeting on wire = %q", string(buf[:n]))
	}
}
