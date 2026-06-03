package cve

import "testing"

func TestHTTPAppBatch2Match(t *testing.T) {
	cases := []struct{ payload, want string }{
		{"GET /GponForm/diag_Form?images/ HTTP/1.1\r\n\r\ndest_host=`id`", "CVE-2018-10562"},
		{"POST /ctrlt/DeviceUpgrade_1 HTTP/1.1\r\n\r\n<NewStatusURL>$(id)", "CVE-2017-17215"},
		{"GET /boaform/admin/formping?target_addr=;id HTTP/1.1\r\n\r\n", "CVE-2020-8958"},
		{"GET /cgi-bin/kerbynet?Action=x509view&type=`id` HTTP/1.1\r\n\r\n", "CVE-2019-12725"},
		{"POST /api/jsonws/invoke HTTP/1.1\r\n\r\ncom.mchange", "CVE-2020-7961"},
		{"GET /flex2gateway/amf HTTP/1.1\r\n\r\n", "CVE-2017-3066"},
		{"GET /_api/web/siteusers HTTP/1.1\r\n\r\n", "CVE-2023-29357"},
		{"GET /jobmanager/logs/..%252f..%252fetc%252fpasswd HTTP/1.1\r\n\r\n", "CVE-2020-17519"},
		{"POST /rest/all/V1/guest-carts/1/estimate-shipping-methods HTTP/1.1\r\n\r\n<!DOCTYPE", "CVE-2024-34102"},
		{"GET /index.php?option=com_fields&view=fields&list[fullordering]=updatexml HTTP/1.1\r\n\r\n", "CVE-2017-8917"},
		{"GET /static/../../../../etc/passwd HTTP/1.1\r\n\r\n", "CVE-2024-23334"},
		{"GET /cgi-bin/cstecgi.cgi?action=login HTTP/1.1\r\n\r\n", "CVE-2022-25075"},
	}
	for _, c := range cases {
		hits := MatchPayload("http", c.payload)
		ok := false
		for _, h := range hits {
			if h.ID == c.want {
				ok = true
			}
		}
		if !ok {
			t.Errorf("payload should detect %s; got %v", c.want, ids(hits))
		}
	}
}
