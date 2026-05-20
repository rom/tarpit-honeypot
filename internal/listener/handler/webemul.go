package handler

import (
	"fmt"
	"strings"
	"time"

	"github.com/rom/tarpit-honeypot/internal/archetype"
	"github.com/rom/tarpit-honeypot/internal/identity"
)

// webemul builds web-server-flavored HTTP responses. The point is that
// a scanner fingerprinting the server (header order, Date format,
// ETag shape, the exact bytes of the default 404 / 403 / 400 error
// page) sees a consistent, version-appropriate Apache (or nginx)
// rather than a generic skeleton. Apache and nginx ship visually
// distinct default error pages; reproducing them defeats the easy
// "this 404 body doesn't match the Server header" honeypot tell.

// webFlavor is derived from the Server header string.
type webFlavor int

const (
	flavorGeneric webFlavor = iota
	flavorApache
	flavorNginx
)

func flavorFromServer(server string) webFlavor {
	switch {
	case strings.HasPrefix(server, "Apache"):
		return flavorApache
	case strings.HasPrefix(server, "nginx"):
		return flavorNginx
	}
	return flavorGeneric
}

// httpDate formats a time in the RFC 7231 IMF-fixdate form Apache and
// nginx both use in the Date / Last-Modified headers.
func httpDate(t time.Time) string {
	return t.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
}

// errorPage returns the response body + Content-Type for an HTTP error
// status in the style of the named flavor. Apache's default pages have
// the characteristic "<address>Apache/2.4.x (Ubuntu) Server at host
// Port 80</address>" footer; nginx's are a centered minimal page with
// its version in the footer.
func errorPage(flavor webFlavor, status int, server, host string) (string, string) {
	title, heading, detail := statusStrings(status)
	switch flavor {
	case flavorApache:
		body := "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n" +
			"<html><head>\n<title>" + title + "</title>\n</head><body>\n" +
			"<h1>" + heading + "</h1>\n<p>" + detail + "</p>\n<hr>\n" +
			"<address>" + server + " Server at " + host + " Port 80</address>\n" +
			"</body></html>\n"
		return body, "text/html; charset=iso-8859-1"
	case flavorNginx:
		body := "<html>\r\n<head><title>" + title + "</title></head>\r\n" +
			"<body>\r\n<center><h1>" + heading + "</h1></center>\r\n" +
			"<hr><center>" + server + "</center>\r\n</body>\r\n</html>\r\n"
		return body, "text/html"
	}
	return "<html><body><h1>" + heading + "</h1></body></html>\n", "text/html"
}

func statusStrings(status int) (title, heading, detail string) {
	switch status {
	case 400:
		return "400 Bad Request", "Bad Request",
			"Your browser sent a request that this server could not understand."
	case 401:
		return "401 Unauthorized", "Unauthorized",
			"This server could not verify that you are authorized to access the document requested."
	case 403:
		return "403 Forbidden", "Forbidden",
			"You don't have permission to access this resource."
	case 404:
		return "404 Not Found", "Not Found",
			"The requested URL was not found on this server."
	case 500:
		return "500 Internal Server Error", "Internal Server Error",
			"The server encountered an internal error or misconfiguration and was unable to complete your request."
	}
	return fmt.Sprintf("%d", status), fmt.Sprintf("%d", status), ""
}

// buildErrorResponse assembles a full flavored HTTP error response with
// the header ordering Apache / nginx actually use. id supplies the
// deployment-unique ETag seed; it may be nil.
func buildErrorResponse(flavor webFlavor, status int, server, host string, id *identity.Identity) string {
	statusLine := statusText(status)
	body, ctype := errorPage(flavor, status, server, host)
	now := time.Now()

	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %s\r\n", statusLine)
	// Apache header order: Date, Server, [WWW-Authenticate], Content-Length,
	// Connection, Content-Type. nginx: Server, Date, Content-Type,
	// Content-Length, Connection.
	switch flavor {
	case flavorNginx:
		fmt.Fprintf(&b, "Server: %s\r\n", server)
		fmt.Fprintf(&b, "Date: %s\r\n", httpDate(now))
		fmt.Fprintf(&b, "Content-Type: %s\r\n", ctype)
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
		if status == 401 {
			b.WriteString("WWW-Authenticate: Basic realm=\"Restricted\"\r\n")
		}
		b.WriteString("Connection: close\r\n")
	default: // Apache + generic
		fmt.Fprintf(&b, "Date: %s\r\n", httpDate(now))
		fmt.Fprintf(&b, "Server: %s\r\n", server)
		if status == 401 {
			b.WriteString("WWW-Authenticate: Basic realm=\"Restricted\"\r\n")
		}
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
		b.WriteString("Connection: close\r\n")
		fmt.Fprintf(&b, "Content-Type: %s\r\n", ctype)
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}

// defaultIndexPage returns the body + Content-Type for GET / on a
// fresh install of the named flavor. Apache ships the famous
// "It works!" page; nginx ships its "Welcome to nginx!" page. Both
// are exact enough to pass a casual fingerprint.
func defaultIndexPage(flavor webFlavor, server string) (string, string) {
	switch flavor {
	case flavorApache:
		return "<html><body><h1>It works!</h1></body></html>\n", "text/html"
	case flavorNginx:
		return "<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n" +
			"<style>\nhtml { color-scheme: light dark; }\n" +
			"body { width: 35em; margin: 0 auto;\n" +
			"font-family: Tahoma, Verdana, Arial, sans-serif; }\n</style>\n</head>\n" +
			"<body>\n<h1>Welcome to nginx!</h1>\n" +
			"<p>If you see this page, the nginx web server is successfully installed and\n" +
			"working. Further configuration is required.</p>\n\n" +
			"<p>For online documentation and support please refer to\n" +
			"<a href=\"http://nginx.org/\">nginx.org</a>.<br/>\n" +
			"Commercial support is available at\n" +
			"<a href=\"http://nginx.com/\">nginx.com</a>.</p>\n\n" +
			"<p><em>Thank you for using nginx.</em></p>\n</body>\n</html>\n", "text/html"
	}
	return "<html><body><h1>It works!</h1></body></html>\n", "text/html"
}

// isSwitchInfoPath matches the device-info / status / topology paths a
// managed switch's web UI exposes.
func isSwitchInfoPath(p string) bool {
	switch p {
	case "/topology", "/status", "/info", "/device", "/device-info",
		"/lldp", "/vlan", "/mrp", "/profinet", "/network":
		return true
	}
	return false
}

// hasSwitchTopology reports whether the archetype carries any
// switch/OT topology data worth rendering.
func hasSwitchTopology(p *archetype.Profile) bool {
	return p != nil && (len(p.MRPRings()) > 0 || len(p.PROFINETDevices()) > 0 ||
		len(p.VLANs()) > 0 || len(p.HMIs()) > 0 || len(p.LLDPNeighbors()) > 0)
}

// switchTopologyHTML renders the archetype's MRP / PROFINET / VLAN /
// HMI / LLDP inventory as an industrial-switch status page. This is
// what makes a scanner walking the device's web UI see a believable
// cell topology rather than an empty page.
func switchTopologyHTML(p *archetype.Profile) string {
	var b strings.Builder
	b.WriteString("<html><head><title>")
	b.WriteString(htmlEscape(p.HTTPTitle()))
	b.WriteString(" — Network</title></head><body>")
	b.WriteString("<h2>" + htmlEscape(p.SNMPSysName()) + " — Network Status</h2>")

	if rings := p.MRPRings(); len(rings) > 0 {
		b.WriteString("<h3>Media Redundancy (MRP)</h3><table border=1><tr><th>Ring</th><th>Role</th><th>Ports</th><th>State</th></tr>")
		for _, r := range rings {
			fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
				htmlEscape(r.Name), htmlEscape(r.Role), intsJoin(r.Ports), htmlEscape(r.State))
		}
		b.WriteString("</table>")
	}
	if vlans := p.VLANs(); len(vlans) > 0 {
		b.WriteString("<h3>VLANs</h3><table border=1><tr><th>ID</th><th>Name</th><th>Ports</th></tr>")
		for _, v := range vlans {
			fmt.Fprintf(&b, "<tr><td>%d</td><td>%s</td><td>%s</td></tr>",
				v.ID, htmlEscape(v.Name), intsJoin(v.Ports))
		}
		b.WriteString("</table>")
	}
	if pds := p.PROFINETDevices(); len(pds) > 0 {
		b.WriteString("<h3>PROFINET Devices</h3><table border=1><tr><th>Station</th><th>IP</th><th>Role</th><th>Vendor</th></tr>")
		for _, d := range pds {
			fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
				htmlEscape(d.StationName), htmlEscape(d.IP), htmlEscape(d.Role), htmlEscape(d.Vendor))
		}
		b.WriteString("</table>")
	}
	if peers := p.LLDPNeighbors(); len(peers) > 0 {
		b.WriteString("<h3>LLDP Neighbors</h3><table border=1><tr><th>Port</th><th>Chassis</th><th>System</th></tr>")
		for _, n := range peers {
			fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>",
				htmlEscape(n.PortID), htmlEscape(n.ChassisID), htmlEscape(n.SystemName))
		}
		b.WriteString("</table>")
	}
	if hmis := p.HMIs(); len(hmis) > 0 {
		b.WriteString("<h3>Connected HMIs</h3><table border=1><tr><th>Name</th><th>IP</th><th>Type</th></tr>")
		for _, h := range hmis {
			fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>",
				htmlEscape(h.Name), htmlEscape(h.IP), htmlEscape(h.Type))
		}
		b.WriteString("</table>")
	}
	b.WriteString("</body></html>")
	return b.String()
}

// htmlEscape is a minimal HTML-attribute/text escaper for the
// archetype-supplied (operator-controlled, but defense-in-depth)
// topology strings.
func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;")
	return r.Replace(s)
}

func intsJoin(xs []int) string {
	var b strings.Builder
	for i, x := range xs {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(itoa(x))
	}
	return b.String()
}

func statusText(status int) string {
	switch status {
	case 200:
		return "200 OK"
	case 400:
		return "400 Bad Request"
	case 401:
		return "401 Unauthorized"
	case 403:
		return "403 Forbidden"
	case 404:
		return "404 Not Found"
	case 500:
		return "500 Internal Server Error"
	}
	return fmt.Sprintf("%d", status)
}
