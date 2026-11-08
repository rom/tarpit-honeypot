package detonate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// capeDetonate uploads a stored sample to a CAPE sandbox, waits for the task to
// report, and extracts the network IOCs from the report. Only called when the
// operator has opted into SubmitSamples and a CAPE URL is configured.
func (d *Detonator) capeDetonate(ctx context.Context, sha256, path string) (*Verdict, error) {
	data, err := readCapped(path, d.cfg.MaxSampleBytes)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	taskID, err := d.capeSubmit(ctx, filepath.Base(path), data)
	if err != nil {
		return nil, err
	}
	if taskID == 0 {
		return nil, fmt.Errorf("cape: no task id")
	}
	if err := d.capePoll(ctx, taskID); err != nil {
		return nil, err
	}
	return d.capeReport(ctx, sha256, taskID)
}

func (d *Detonator) capeSubmit(ctx context.Context, name string, data []byte) (int, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", name)
	if err != nil {
		return 0, err
	}
	if _, err := fw.Write(data); err != nil {
		return 0, err
	}
	_ = mw.Close()

	if err := d.wait(ctx); err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.capeURL("/apiv2/tasks/create/file/"), &buf)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	d.capeAuth(req)
	resp, err := d.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return 0, fmt.Errorf("cape submit: status %d", resp.StatusCode)
	}
	// CAPE returns either {"data":{"task_ids":[N]}} or {"task_id":N} / {"data":{"task_id":N}}.
	var r struct {
		TaskID int `json:"task_id"`
		Data   struct {
			TaskID  int   `json:"task_id"`
			TaskIDs []int `json:"task_ids"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &r) != nil {
		return 0, fmt.Errorf("cape submit: bad json")
	}
	switch {
	case len(r.Data.TaskIDs) > 0:
		return r.Data.TaskIDs[0], nil
	case r.Data.TaskID != 0:
		return r.Data.TaskID, nil
	default:
		return r.TaskID, nil
	}
}

func (d *Detonator) capePoll(ctx context.Context, taskID int) error {
	every := d.cfg.CAPE.PollEvery
	if every <= 0 {
		every = 10 * time.Second
	}
	maxWait := d.cfg.CAPE.MaxWait
	if maxWait <= 0 {
		maxWait = 3 * time.Minute
	}
	deadline := time.Now().Add(maxWait)
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		status, err := d.capeStatus(ctx, taskID)
		if err == nil && (status == "reported" || status == "completed") {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("cape: task %d not reported within %s (last status %q)", taskID, maxWait, status)
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (d *Detonator) capeStatus(ctx context.Context, taskID int) (string, error) {
	body, status, err := d.capeGet(ctx, fmt.Sprintf("/apiv2/tasks/view/%d/", taskID))
	if err != nil || status != http.StatusOK {
		return "", fmt.Errorf("cape view: status %d err %v", status, err)
	}
	var r struct {
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	_ = json.Unmarshal(body, &r)
	return r.Data.Status, nil
}

func (d *Detonator) capeReport(ctx context.Context, sha256 string, taskID int) (*Verdict, error) {
	body, status, err := d.capeGet(ctx, fmt.Sprintf("/apiv2/tasks/get/report/%d/", taskID))
	if err != nil || status != http.StatusOK {
		return nil, fmt.Errorf("cape report: status %d err %v", status, err)
	}
	var r struct {
		Network struct {
			Domains []struct {
				Domain string `json:"domain"`
			} `json:"domains"`
			Hosts []json.RawMessage `json:"hosts"`
			HTTP  []struct {
				Host string `json:"host"`
				URI  string `json:"uri"`
				URL  string `json:"url"`
			} `json:"http"`
		} `json:"network"`
		Dropped []struct {
			SHA256 string `json:"sha256"`
		} `json:"dropped"`
	}
	if json.Unmarshal(body, &r) != nil {
		return nil, fmt.Errorf("cape report: bad json")
	}
	v := &Verdict{SHA256: sha256, Source: "cape", Found: true}
	for _, x := range r.Network.Domains {
		if x.Domain != "" {
			v.Domains = append(v.Domains, x.Domain)
		}
	}
	for _, h := range r.Network.Hosts {
		// hosts entries are either a bare "1.2.3.4" string or {"ip":"1.2.3.4"}.
		var s string
		if json.Unmarshal(h, &s) == nil && s != "" {
			v.IPs = append(v.IPs, s)
			continue
		}
		var obj struct {
			IP string `json:"ip"`
		}
		if json.Unmarshal(h, &obj) == nil && obj.IP != "" {
			v.IPs = append(v.IPs, obj.IP)
		}
	}
	for _, x := range r.Network.HTTP {
		switch {
		case x.URL != "":
			v.URLs = append(v.URLs, x.URL)
		case x.Host != "" && x.URI != "":
			v.URLs = append(v.URLs, "http://"+x.Host+x.URI)
		}
	}
	for _, x := range r.Dropped {
		if validSHA256(x.SHA256) {
			v.Dropped = append(v.Dropped, strings.ToLower(x.SHA256))
		}
	}
	v.Domains, v.IPs, v.URLs, v.Dropped = uniq(v.Domains), uniq(v.IPs), uniq(v.URLs), uniq(v.Dropped)
	return v, nil
}

func (d *Detonator) capeGet(ctx context.Context, path string) ([]byte, int, error) {
	if err := d.wait(ctx); err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.capeURL(path), nil)
	if err != nil {
		return nil, 0, err
	}
	d.capeAuth(req)
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return body, resp.StatusCode, nil
}

func (d *Detonator) capeURL(path string) string {
	return strings.TrimRight(d.cfg.CAPE.URL, "/") + path
}

func (d *Detonator) capeAuth(req *http.Request) {
	if d.capeTk != "" {
		req.Header.Set("Authorization", "Token "+d.capeTk)
	}
}

// readCapped reads up to max bytes from path. Returns an error for an
// oversized sample so a huge dropper can't be uploaded or buffered.
func readCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > max {
		return nil, fmt.Errorf("sample %s is %d bytes (> cap %d)", filepath.Base(path), fi.Size(), max)
	}
	return io.ReadAll(io.LimitReader(f, max))
}
