package handler

import "testing"

func TestSMTPClassifyMessage(t *testing.T) {
	// A phishing message: subject + from headers extracted, credential-lure link
	// flagged.
	phish := "From: \"IT Helpdesk\" <it@evil.example>\r\n" +
		"Subject: URGENT: verify your account password\r\n" +
		"\r\n" +
		"Please login at http://evil.example/verify to keep your account.\r\n"
	var res Result
	res.Meta = map[string]any{}
	smtpClassifyMessage(&res, phish)
	if res.Meta["mail_subject"] != "URGENT: verify your account password" {
		t.Errorf("mail_subject = %v", res.Meta["mail_subject"])
	}
	if res.Meta["mail_header_from"] != `"IT Helpdesk" <it@evil.example>` {
		t.Errorf("mail_header_from = %v", res.Meta["mail_header_from"])
	}
	anoms, _ := res.Meta["anomalies"].([]string)
	if !containsStr(anoms, "smtp-phishing-content") {
		t.Errorf("phishing not flagged: %v", anoms)
	}

	// A message with a base64 attachment is flagged as malware delivery.
	var res2 Result
	res2.Meta = map[string]any{}
	mal := "Subject: invoice\r\n\r\n" +
		"Content-Type: application/zip; name=\"invoice.zip\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\nUEsDBAoAAAAA\r\n"
	smtpClassifyMessage(&res2, mal)
	anoms2, _ := res2.Meta["anomalies"].([]string)
	if !containsStr(anoms2, "smtp-attachment") {
		t.Errorf("attachment not flagged: %v", anoms2)
	}

	// A benign plain message flags nothing.
	var res3 Result
	res3.Meta = map[string]any{}
	smtpClassifyMessage(&res3, "Subject: hi\r\n\r\njust saying hello\r\n")
	if a, _ := res3.Meta["anomalies"].([]string); len(a) != 0 {
		t.Errorf("benign message should not flag: %v", a)
	}
}
