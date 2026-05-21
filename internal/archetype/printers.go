package archetype

// printerArchetypes models network printers / multi-function devices (MFDs)
// across the major vendors. Each carries the distinctive embedded-web-server
// (EWS) Server header + title, the vendor SNMP enterprise OID + sysDescr a
// Printer-MIB walk returns, the vendor MAC OUI, and the printer service set
// (raw/JetDirect 9100, IPP 631, LPD 515, SNMP 161, web 80/443) so a
// printer-discovery scan (nmap, PRET, snmpwalk, Shodan) sees a coherent box.
//
// Family is "printer" for all of them; the per-vendor identity lives in the
// banners/OIDs so the distro-completeness tests don't apply.
var printerArchetypes = map[string]*Profile{
	"brother-printer":       brotherPrinter(),
	"canon-imagerunner":     canonImageRunner(),
	"epson-workforce":       epsonWorkForce(),
	"xerox-versalink":       xeroxVersaLink(),
	"lexmark-printer":       lexmarkPrinter(),
	"ricoh-mfp":             ricohMFP(),
	"konica-minolta-bizhub": konicaMinoltaBizhub(),
	"kyocera-ecosys":        kyoceraEcosys(),
	"sharp-mfp":             sharpMFP(),
	"zebra-printer":         zebraPrinter(),
}

// printerServices is the canonical MFD service set: web EWS, the three
// print transports, and SNMP.
func printerServices() []DefaultService {
	return []DefaultService{
		{Port: 80, Handler: "http", Note: "EWS web"},
		{Port: 443, Handler: "https", Note: "EWS web (TLS)"},
		{Port: 9100, Handler: "pjl", Note: "JetDirect / raw print"},
		{Port: 631, Handler: "ipp", Note: "IPP"},
		{Port: 515, Handler: "lpd", Note: "LPD"},
		{Port: 161, Handler: "snmp", Note: "SNMP"},
	}
}

// printerEWS renders a believable embedded-web-server status page: model,
// Ready status, supply (toner/drum) levels, a page count, and the nav a
// real MFP exposes. A scanner / human poking the web UI sees a plausible
// device; nothing is real.
func printerEWS(model string) string {
	return "<!DOCTYPE html><html><head><title>" + model + "</title>" +
		"<meta name=viewport content=\"width=device-width\"></head><body>" +
		"<h1>" + model + "</h1><p>Device Status: <b>Ready</b></p>" +
		"<table><tr><th>Supply</th><th>Level</th></tr>" +
		"<tr><td>Black Toner</td><td>72%</td></tr>" +
		"<tr><td>Cyan Toner</td><td>61%</td></tr>" +
		"<tr><td>Magenta Toner</td><td>58%</td></tr>" +
		"<tr><td>Yellow Toner</td><td>64%</td></tr>" +
		"<tr><td>Drum Unit</td><td>83%</td></tr></table>" +
		"<p>Page Count: 18342</p>" +
		"<ul><li>Status</li><li>Print Jobs</li><li>Address Book</li>" +
		"<li>Settings</li><li>Network</li><li>Security</li></ul></body></html>"
}

func brotherPrinter() *Profile {
	return &Profile{
		Name: "brother-printer", DisplayName: "Brother HL-L8260CDW (printer)", Family: "printer",
		httpServer:   "debut/1.20",
		httpTitle:    "Brother HL-L8260CDW series",
		httpBodyHTML: printerEWS("Brother HL-L8260CDW series"),
		httpHeaders:  map[string]string{"X-Frame-Options": "SAMEORIGIN"},
		snmpSysDescr: "Brother HL-L8260CDW series", snmpSysName: "BRN3C2AF4",
		snmpSysObjectID: ".1.3.6.1.4.1.2435.2.3.9.1",
		macOUI:          [3]byte{0x30, 0x05, 0x5c}, // Brother
		icmpTTL:         64,
		defaultServices: printerServices(),
		quirks:          []string{"printer", "pjl"},
	}
}

func canonImageRunner() *Profile {
	return &Profile{
		Name: "canon-imagerunner", DisplayName: "Canon imageRUNNER ADVANCE (MFP)", Family: "printer",
		httpServer:   "Canon HTTP Server",
		httpTitle:    "Canon : imageRUNNER ADVANCE",
		httpBodyHTML: printerEWS("Canon imageRUNNER ADVANCE C5550i"),
		httpHeaders:  map[string]string{"X-Frame-Options": "SAMEORIGIN"},
		snmpSysDescr: "Canon iR-ADV C5550i /P", snmpSysName: "CANON3F2A1C",
		snmpSysObjectID: ".1.3.6.1.4.1.1602.4.7",
		macOUI:          [3]byte{0x2c, 0x9e, 0xfc}, // Canon
		icmpTTL:         64,
		defaultServices: printerServices(),
		quirks:          []string{"printer", "pjl"},
	}
}

func epsonWorkForce() *Profile {
	return &Profile{
		Name: "epson-workforce", DisplayName: "Epson WorkForce Pro (MFP)", Family: "printer",
		httpServer:   "EPSON-HTTP/1.0",
		httpTitle:    "EPSON WorkForce Pro WF-C5790",
		httpBodyHTML: printerEWS("EPSON WorkForce Pro WF-C5790"),
		httpHeaders:  map[string]string{"X-Frame-Options": "SAMEORIGIN"},
		snmpSysDescr: "EPSON WF-C5790 Series", snmpSysName: "EPSONA4EE57",
		snmpSysObjectID: ".1.3.6.1.4.1.1248.1.2.2.1.1",
		macOUI:          [3]byte{0xa4, 0xee, 0x57}, // Epson
		icmpTTL:         64,
		defaultServices: printerServices(),
		quirks:          []string{"printer", "pjl"},
	}
}

func xeroxVersaLink() *Profile {
	return &Profile{
		Name: "xerox-versalink", DisplayName: "Xerox VersaLink C405 (MFP)", Family: "printer",
		httpServer:   "Xerox_MicroServer/Xerox(R)",
		httpTitle:    "Xerox® VersaLink® C405",
		httpBodyHTML: printerEWS("Xerox VersaLink C405"),
		httpHeaders:  map[string]string{"X-Frame-Options": "SAMEORIGIN"},
		snmpSysDescr: "Xerox VersaLink C405; SS 73.61.21; UI 1.5.2", snmpSysName: "Xerox9C934E",
		snmpSysObjectID: ".1.3.6.1.4.1.253.8.62.1.25.1",
		macOUI:          [3]byte{0x9c, 0x93, 0x4e}, // Xerox
		icmpTTL:         64,
		cveVulns:        []string{"CVE-2024-12510"},
		defaultServices: printerServices(),
		quirks:          []string{"printer", "pjl"},
	}
}

func lexmarkPrinter() *Profile {
	return &Profile{
		Name: "lexmark-printer", DisplayName: "Lexmark MX622 (MFP)", Family: "printer",
		httpServer:   "Lexmark_Web_Server",
		httpTitle:    "Lexmark MX622",
		httpBodyHTML: printerEWS("Lexmark MX622adhe"),
		httpHeaders:  map[string]string{"X-Frame-Options": "SAMEORIGIN"},
		snmpSysDescr: "Lexmark MX622", snmpSysName: "ET0021B7",
		snmpSysObjectID: ".1.3.6.1.4.1.641.6",
		macOUI:          [3]byte{0x00, 0x21, 0xb7}, // Lexmark
		icmpTTL:         64,
		cveVulns:        []string{"CVE-2023-26067"},
		defaultServices: printerServices(),
		quirks:          []string{"printer", "pjl"},
	}
}

func ricohMFP() *Profile {
	return &Profile{
		Name: "ricoh-mfp", DisplayName: "Ricoh IM C3000 (MFP)", Family: "printer",
		httpServer:   "Web-Server/3.0",
		httpTitle:    "RICOH IM C3000",
		httpBodyHTML: printerEWS("RICOH IM C3000"),
		httpHeaders:  map[string]string{"X-Frame-Options": "SAMEORIGIN"},
		snmpSysDescr: "RICOH IM C3000", snmpSysName: "RNP002673",
		snmpSysObjectID: ".1.3.6.1.4.1.367.1.1",
		macOUI:          [3]byte{0x00, 0x26, 0x73}, // Ricoh
		icmpTTL:         64,
		defaultServices: printerServices(),
		quirks:          []string{"printer", "pjl"},
	}
}

func konicaMinoltaBizhub() *Profile {
	return &Profile{
		Name: "konica-minolta-bizhub", DisplayName: "Konica Minolta bizhub C284e (MFP)", Family: "printer",
		httpServer:   "KM-MFP-Http/1.0",
		httpTitle:    "bizhub C284e",
		httpBodyHTML: printerEWS("KONICA MINOLTA bizhub C284e"),
		httpHeaders:  map[string]string{"X-Frame-Options": "SAMEORIGIN"},
		snmpSysDescr: "KONICA MINOLTA bizhub C284e", snmpSysName: "KMBT00206B",
		snmpSysObjectID: ".1.3.6.1.4.1.18334.1.1.1.1.1",
		macOUI:          [3]byte{0x00, 0x20, 0x6b}, // Konica Minolta
		icmpTTL:         64,
		defaultServices: printerServices(),
		quirks:          []string{"printer", "pjl"},
	}
}

func kyoceraEcosys() *Profile {
	return &Profile{
		Name: "kyocera-ecosys", DisplayName: "Kyocera ECOSYS M3550idn (MFP)", Family: "printer",
		httpServer:   "KM-httpd/1.0",
		httpTitle:    "Kyocera Command Center RX",
		httpBodyHTML: printerEWS("Kyocera ECOSYS M3550idn"),
		httpHeaders:  map[string]string{"X-Frame-Options": "SAMEORIGIN"},
		snmpSysDescr: "Kyocera ECOSYS M3550idn", snmpSysName: "KM00C0EE",
		snmpSysObjectID: ".1.3.6.1.4.1.1347.43",
		macOUI:          [3]byte{0x00, 0xc0, 0xee}, // Kyocera
		icmpTTL:         64,
		cveVulns:        []string{"CVE-2022-1026"},
		defaultServices: printerServices(),
		quirks:          []string{"printer", "pjl"},
	}
}

func sharpMFP() *Profile {
	return &Profile{
		Name: "sharp-mfp", DisplayName: "Sharp MX-3071 (MFP)", Family: "printer",
		httpServer:   "Boa/0.94.13",
		httpTitle:    "SHARP MX-3071",
		httpBodyHTML: printerEWS("SHARP MX-3071"),
		httpHeaders:  map[string]string{"X-Frame-Options": "SAMEORIGIN"},
		snmpSysDescr: "SHARP MX-3071", snmpSysName: "SHARP002265",
		snmpSysObjectID: ".1.3.6.1.4.1.2385.1.1",
		macOUI:          [3]byte{0x00, 0x22, 0x65}, // Sharp
		icmpTTL:         64,
		defaultServices: printerServices(),
		quirks:          []string{"printer", "pjl"},
	}
}

// zebraPrinter is a label printer: it speaks ZPL (not PJL/PostScript) on
// the raw port and exposes a slimmer service set — no IPP/LPD on most
// models. The pjl handler still recognizes the ZPL on 9100.
func zebraPrinter() *Profile {
	return &Profile{
		Name: "zebra-printer", DisplayName: "Zebra ZT411 (label printer)", Family: "printer",
		httpServer: "ZebraNet",
		httpTitle:  "Zebra Technologies ZTC ZT411-203dpi",
		httpBodyHTML: "<html><head><title>Zebra ZT411</title></head><body><h1>Zebra Technologies</h1>" +
			"<p>ZTC ZT411-203dpi ZPL</p><p>Status: READY</p>" +
			"<ul><li>Printer Home</li><li>View Printer Configuration</li>" +
			"<li>Directory Listing</li><li>Network Configuration</li></ul></body></html>",
		httpHeaders:  map[string]string{},
		snmpSysDescr: "ZTC ZT411-203dpi, V93.21.06Z", snmpSysName: "ZBR00074D",
		snmpSysObjectID: ".1.3.6.1.4.1.10642.1",
		macOUI:          [3]byte{0x00, 0x07, 0x4d}, // Zebra
		icmpTTL:         64,
		defaultServices: []DefaultService{
			{Port: 80, Handler: "http", Note: "ZebraNet web"},
			{Port: 9100, Handler: "pjl", Note: "raw print (ZPL)"},
			{Port: 161, Handler: "snmp", Note: "SNMP"},
		},
		quirks: []string{"printer", "zpl", "label"},
	}
}
