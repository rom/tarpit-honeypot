package ui

import (
	"fmt"
	"strings"

	"github.com/rom/tarpit-honeypot/internal/event"
)

// protoField is one labeled request field for the event-detail protocol section.
type protoField struct {
	Label string
	Value string
}

// protoGroup is a titled set of protocol request fields (e.g. "DNS query",
// "SSH handshake"), the non-HTTP counterpart of the detail page's HTTP-request
// section.
type protoGroup struct {
	Title  string
	Fields []protoField
}

// protoFieldSpec maps a captured meta key to the human label shown for it.
type protoFieldSpec struct {
	key, label string
}

// protoSpecs defines, per (normalized) handler, the title and the ordered
// request fields to surface on the detail page. The HTTP handler keeps its own
// bespoke section in the template; these cover the other protocols the honeypot
// speaks so their captured fields read as a labeled table instead of a raw meta
// blob. Keys that aren't present on a given event are simply skipped.
var protoSpecs = map[string]struct {
	title  string
	fields []protoFieldSpec
}{
	"dns": {"DNS query", []protoFieldSpec{
		{"qname", "query name"}, {"qtype_name", "query type"}, {"qtype", "type code"},
		{"dns_queries", "all queries"}, {"zone_transfer_served", "AXFR zone transfer served"},
		{"malformed_dns", "malformed packet"},
	}},
	"ssh": {"SSH handshake & client", []protoFieldSpec{
		{"client_id", "client banner"}, {"ssh_client_openssh_version", "OpenSSH version"},
		{"hassh", "HASSH"}, {"ssh_kex_negotiated", "negotiated KEX"},
		{"ssh_kex_ciphers_c2s", "ciphers (c→s)"}, {"ssh_kex_macs_c2s", "MACs (c→s)"},
		{"ssh_kex_hostkeys", "host-key algs"}, {"ssh_subsystem", "subsystem"},
		{"max_password_len", "max password length"}, {"accepted_user", "accepted login"},
	}},
	"smtp": {"SMTP envelope", []protoFieldSpec{
		{"helo", "HELO/EHLO"}, {"mail_from", "MAIL FROM"}, {"rcpt_to", "RCPT TO"},
		{"mail_header_from", "header From"}, {"mail_subject", "subject"},
		{"vrfy_user", "VRFY user"}, {"expn_list", "EXPN list"}, {"starttls", "STARTTLS"},
	}},
	"snmp": {"SNMP request", []protoFieldSpec{
		{"snmp_version", "version"}, {"community", "community"}, {"snmp_pdu", "PDU type"},
		{"varbind_oids", "requested OIDs"}, {"snmp_set", "SET write"},
		{"snmp_v3_user", "v3 user"}, {"trap_type", "trap type"},
		{"snmp_default_community", "default community"},
	}},
	"ntp": {"NTP request", []protoFieldSpec{
		{"ntp_request", "request"}, {"ntp_impl", "mode-7 implementation"},
		{"ntp_request_code", "mode-7 request code"}, {"ntp_control", "mode-6 control"},
		{"ntp_control_opcode", "mode-6 opcode"}, {"ntp_authenticated", "authenticated"},
	}},
	"rdp": {"RDP client", []protoFieldSpec{
		{"cookie", "mstshash cookie"}, {"username", "username"}, {"ntlm_user", "NTLM user"},
		{"ntlm_domain", "NTLM domain"}, {"nla", "NLA/CredSSP"}, {"tls_version", "TLS version"},
	}},
	"ftp": {"FTP session", []protoFieldSpec{
		{"user", "username"}, {"pass", "password"}, {"ftp_upload_name", "uploaded file"},
		{"ftp_upload_size", "upload size"}, {"ftp_upload_sha256", "upload sha256"},
		{"ftp_bounce_target", "FXP/bounce target"}, {"retrieved", "retrieved file"},
		{"authed", "authenticated"},
	}},
	"telnet": {"Telnet session", []protoFieldSpec{
		{"user_attempt", "username"}, {"pass_attempt", "password"},
		{"terminal_type", "terminal type"}, {"terminal_speed", "terminal speed"},
		{"window_size", "window size"}, {"accepted_user", "accepted login"},
	}},

	// --- OT / ICS / BMS protocols: the decoded command/function first, so the
	// specific operation (Modbus "Read Holding Registers", HART-IP command, S7
	// "Read Var", DNP3 application function, …) reads at the top of the section.
	"modbus": {"Modbus command", []protoFieldSpec{
		{"function_name", "function"}, {"function_code", "function code"},
		{"unit_id", "unit id"}, {"umas_function_code", "UMAS function code"},
		{"modbus_fcs_seen", "function codes seen"}, {"modbus_units_seen", "unit ids swept"},
		{"transaction_id", "transaction id"},
	}},
	"s7": {"S7comm command", []protoFieldSpec{
		{"s7_function", "function"}, {"s7_write_area", "write area"},
		{"s7_write_db", "write DB"}, {"s7_write_byte", "write byte offset"},
		{"s7_szl_id", "SZL id (fingerprint)"}, {"cotp_type", "COTP PDU"},
	}},
	"s7comm_plus": {"S7comm-Plus command", []protoFieldSpec{
		{"s7plus_function", "function"}, {"s7plus_opcode", "opcode"},
		{"s7plus_family", "family"}, {"s7plus_version", "protocol version"},
		{"cotp_type", "COTP PDU"},
	}},
	"dnp3": {"DNP3 command", []protoFieldSpec{
		{"dnp3_app_function", "application function"}, {"dnp3_function", "link function"},
		{"dnp3_src", "source address"}, {"dnp3_dest", "destination address"},
	}},
	"hartip": {"HART-IP command", []protoFieldSpec{
		{"hartip_msg_id", "command"}, {"hartip_msg_type", "message type"},
		{"hartip_version", "version"},
	}},
	"iec104": {"IEC 60870-5-104 command", []protoFieldSpec{
		{"control_type", "frame / command"}, {"frames", "frame count"},
	}},
	"bacnet": {"BACnet command", []protoFieldSpec{
		{"apdu_service", "APDU service"}, {"bvlc_func", "BVLC function"},
		{"bacnet_write_priority", "write priority"},
	}},
	"bacnet_sc": {"BACnet/SC command", []protoFieldSpec{
		{"service", "service"}, {"bvlc_sc_functions", "BVLC-SC functions"},
		{"bacnet_sc_role", "role"}, {"device_uuid", "device UUID"},
	}},
	"ethernetip": {"EtherNet/IP command", []protoFieldSpec{
		{"command", "command"}, {"cip_service", "CIP service"}, {"cip_tag", "CIP tag"},
		{"command_code", "command code"}, {"session_handle", "session handle"},
	}},
	"fins": {"OMRON FINS command", []protoFieldSpec{
		{"command", "command"}, {"mem_area_name", "memory area"},
		{"mem_addr", "memory address"}, {"mem_count", "item count"},
		{"mrc", "main request code"},
	}},
	"melsec": {"MELSEC/SLMP command", []protoFieldSpec{
		{"command_name", "command"}, {"command", "command code"},
		{"subcommand", "subcommand"},
	}},
	"knx": {"KNXnet/IP command", []protoFieldSpec{
		{"service", "service"}, {"op", "operation"}, {"knx_apci", "APCI"},
		{"cemi_msg_code", "cEMI message code"}, {"knx_dst", "destination group"},
		{"knx_src", "source address"},
	}},
	"opcua": {"OPC UA command", []protoFieldSpec{
		{"opcua_service", "service"}, {"message_type", "message type"},
		{"opcua_message", "message"}, {"endpoint_url", "endpoint URL"},
		{"opcua_security_policy", "security policy"},
	}},
	"coap": {"CoAP request", []protoFieldSpec{
		{"code", "method / code"}, {"uri_path", "URI path"}, {"type", "message type"},
	}},
	"mqtt": {"MQTT control packet", []protoFieldSpec{
		{"packet_type", "packet type"},
	}},

	// --- More ICS / IIoT fieldbus & PLC protocols ------------------------
	"ads": {"Beckhoff ADS/AMS command", []protoFieldSpec{
		{"ads_command", "command"}, {"ams_udp_service", "AMS UDP service"},
	}},
	"slmp": {"MELSEC SLMP command", []protoFieldSpec{
		{"slmp_command", "command"},
	}},
	"powerlink": {"Ethernet POWERLINK", []protoFieldSpec{
		{"epl_message_type", "message type"},
	}},
	"profinet": {"PROFINET command", []protoFieldSpec{
		{"profinet_operation", "operation"}, {"profinet_opnum", "opnum"},
	}},
	"secs_gem": {"SECS/GEM message", []protoFieldSpec{
		{"secs_stream", "stream"}, {"secs_function", "function"},
	}},
	"wdbrpc": {"VxWorks WDB RPC", []protoFieldSpec{
		{"wdb_op", "operation"},
	}},
	"crimson": {"Red Lion Crimson", []protoFieldSpec{
		{"crimson_request", "request"},
	}},
	"ge_egd": {"GE EGD command", []protoFieldSpec{
		{"egd_request_id", "request id"},
	}},
	"ge_srtp": {"GE SRTP command", []protoFieldSpec{
		{"srtp_request_type", "request type"},
	}},
	"roc_plus": {"Emerson ROC+ command", []protoFieldSpec{
		{"roc_opcode", "opcode"},
	}},
	"tristation": {"TriStation command", []protoFieldSpec{
		{"ts_msg_type", "message type"}, {"ts_msg", "message"},
	}},
	"pcom": {"Unitronics PCOM command", []protoFieldSpec{
		{"pcom_request", "request"},
	}},
	"mms": {"MMS (IEC 61850) command", []protoFieldSpec{
		{"mms_service", "service"},
	}},
	"atg": {"Veeder-Root ATG command", []protoFieldSpec{
		{"atg_command", "command"},
	}},
	"ethercat": {"EtherCAT command", []protoFieldSpec{
		{"ethercat_cmd", "command"},
	}},
	"focas": {"FANUC FOCAS command", []protoFieldSpec{
		{"focas_opcode", "opcode"},
	}},
	"fox": {"Niagara Fox command", []protoFieldSpec{
		{"fox_request", "request"},
	}},
	"pcworx": {"Phoenix PCWorx command", []protoFieldSpec{
		{"pcworx_opcode", "opcode"},
	}},
	"proconos": {"ProConOS command", []protoFieldSpec{
		{"proconos_opcode", "opcode"},
	}},
	"c37118": {"IEEE C37.118 command", []protoFieldSpec{
		{"c37118_command", "command"},
	}},
	"synchrophasor": {"IEEE C37.118 synchrophasor", []protoFieldSpec{
		{"c37118_frame_type", "frame type"}, {"c37118_id_code", "ID code"},
	}},
	"lontalk": {"LonTalk command", []protoFieldSpec{
		{"lon_packet_type", "packet type"},
	}},
	"osdp": {"OSDP command", []protoFieldSpec{
		{"osdp_command", "command"},
	}},
	"mbus": {"M-Bus command", []protoFieldSpec{
		{"mbus_function", "function"},
	}},

	// --- Building automation (BAS/BMS) -----------------------------------
	"danfoss_aksm": {"Danfoss AK-SM command", []protoFieldSpec{
		{"xml_action", "StoreView action"}, {"method", "HTTP method"},
	}},

	// --- Medical / clinical (MedTech) ------------------------------------
	"hl7": {"HL7 message", []protoFieldSpec{
		{"hl7_message_type", "message type"},
	}},
	"dicom": {"DICOM command", []protoFieldSpec{
		{"dicom_dimse_command", "DIMSE command"},
	}},
	"astm": {"ASTM record", []protoFieldSpec{
		{"astm_record", "record type"}, {"astm_phase", "phase"},
	}},
	"poct1": {"POCT1 message", []protoFieldSpec{
		{"poct1_msg", "message"},
	}},
	"fhir": {"FHIR request", []protoFieldSpec{
		{"fhir_resource", "resource"},
	}},
}

// normalizeHandlerForProto folds TLS / variant handler names onto the base
// protocol whose field spec applies.
func normalizeHandlerForProto(h string) string {
	switch h {
	case "dns_tcp":
		return "dns"
	case "ssh_interactive":
		return "ssh"
	case "smtp_recv", "smtps", "submission":
		return "smtp"
	case "ftps":
		return "ftp"
	// OT/ICS/BMS UDP + TLS variants and aliases fold onto their base spec.
	case "modbus_security", "modbuss", "modbus_udp", "modbus_deep":
		return "modbus"
	case "s7comm":
		return "s7"
	case "dnp3_udp", "dnp3_state":
		return "dnp3"
	case "hartip_udp":
		return "hartip"
	case "enip_udp":
		return "ethernetip"
	case "fins_tcp":
		return "fins"
	case "bacnet_scs":
		return "bacnet_sc"
	case "mqtts":
		return "mqtt"
	case "opcua_session", "opcua_state":
		return "opcua"
	case "ads_discovery":
		return "ads"
	case "gesrtp":
		return "ge_srtp"
	case "pcom_udp":
		return "pcom"
	case "danfoss_aksms":
		return "danfoss_aksm"
	case "hl7s":
		return "hl7"
	case "dicoms":
		return "dicom"
	case "fhirs":
		return "fhir"
	}
	return h
}

// protocolDetailKeys is every meta key surfaced by protocolFields, so the
// catch-all meta table drops them (they already show in a labeled section).
var protocolDetailKeys = func() map[string]bool {
	m := map[string]bool{}
	for _, spec := range protoSpecs {
		for _, f := range spec.fields {
			m[f.key] = true
		}
	}
	return m
}()

// protocolFields returns the labeled request-field groups for a non-HTTP event,
// the counterpart of the detail page's HTTP-request section. It is empty for
// handlers without a spec (their fields stay in the generic meta table) and for
// any field not captured on this event.
func protocolFields(ev *event.Event) []protoGroup {
	if ev == nil || ev.Meta == nil {
		return nil
	}
	spec, ok := protoSpecs[normalizeHandlerForProto(ev.Handler)]
	if !ok {
		return nil
	}
	var fields []protoField
	for _, f := range spec.fields {
		if v := metaDisplay(ev.Meta, f.key); v != "" {
			fields = append(fields, protoField{Label: f.label, Value: v})
		}
	}
	if len(fields) == 0 {
		return nil
	}
	return []protoGroup{{Title: spec.title, Fields: fields}}
}

// otCommandSpec names, per base OT handler, a short protocol label and the
// primary meta key holding the decoded command/function (with a fallback key).
// It drives the single prominent "OT command" line on the detail page; the full
// per-protocol field table comes from protoSpecs above.
var otCommandSpec = map[string]struct{ proto, key, alt string }{
	"modbus":      {"Modbus", "function_name", "function_code"},
	"s7":          {"S7comm", "s7_function", ""},
	"s7comm_plus": {"S7comm-Plus", "s7plus_function", "s7plus_opcode"},
	"dnp3":        {"DNP3", "dnp3_app_function", "dnp3_function"},
	"hartip":      {"HART-IP", "hartip_msg_id", ""},
	"iec104":      {"IEC-104", "control_type", ""},
	"bacnet":      {"BACnet", "apdu_service", "bvlc_func"},
	"bacnet_sc":   {"BACnet/SC", "service", ""},
	"ethernetip":  {"EtherNet/IP", "command", "cip_service"},
	"fins":        {"OMRON FINS", "command", "mem_area_name"},
	"melsec":      {"MELSEC/SLMP", "command_name", "command"},
	"knx":         {"KNXnet/IP", "service", "op"},
	"opcua":       {"OPC UA", "opcua_service", "message_type"},
	"coap":        {"CoAP", "code", "uri_path"},
	"mqtt":        {"MQTT", "packet_type", ""},
	// More ICS / IIoT fieldbus & PLC protocols.
	"ads":           {"Beckhoff ADS", "ads_command", "ams_udp_service"},
	"slmp":          {"MELSEC SLMP", "slmp_command", ""},
	"powerlink":     {"POWERLINK", "epl_message_type", ""},
	"profinet":      {"PROFINET", "profinet_operation", "profinet_opnum"},
	"secs_gem":      {"SECS/GEM", "secs_function", "secs_stream"},
	"wdbrpc":        {"VxWorks WDB", "wdb_op", ""},
	"crimson":       {"Red Lion Crimson", "crimson_request", ""},
	"ge_egd":        {"GE EGD", "egd_request_id", ""},
	"ge_srtp":       {"GE SRTP", "srtp_request_type", ""},
	"roc_plus":      {"Emerson ROC+", "roc_opcode", ""},
	"tristation":    {"TriStation", "ts_msg_type", "ts_msg"},
	"pcom":          {"Unitronics PCOM", "pcom_request", ""},
	"mms":           {"MMS", "mms_service", ""},
	"atg":           {"Veeder-Root ATG", "atg_command", ""},
	"ethercat":      {"EtherCAT", "ethercat_cmd", ""},
	"focas":         {"FANUC FOCAS", "focas_opcode", ""},
	"fox":           {"Niagara Fox", "fox_request", ""},
	"pcworx":        {"Phoenix PCWorx", "pcworx_opcode", ""},
	"proconos":      {"ProConOS", "proconos_opcode", ""},
	"c37118":        {"IEEE C37.118", "c37118_command", ""},
	"synchrophasor": {"IEEE C37.118", "c37118_frame_type", ""},
	"lontalk":       {"LonTalk", "lon_packet_type", ""},
	"osdp":          {"OSDP", "osdp_command", ""},
	"mbus":          {"M-Bus", "mbus_function", ""},
	// Building automation (BAS/BMS).
	"danfoss_aksm": {"Danfoss AK-SM", "xml_action", "method"},
	// Medical / clinical (MedTech).
	"hl7":   {"HL7", "hl7_message_type", ""},
	"dicom": {"DICOM", "dicom_dimse_command", ""},
	"astm":  {"ASTM", "astm_record", "astm_phase"},
	"poct1": {"POCT1", "poct1_msg", ""},
	"fhir":  {"FHIR", "fhir_resource", ""},
}

// otCommand returns the specific decoded command/function for an OT event plus a
// short protocol label — e.g. ("Read Holding Registers", "Modbus") or ("read",
// "HART-IP"). It returns empty strings for non-OT events (and OT events with no
// decoded command), so the detail page shows the "OT command" line only when
// there is a real operation to name.
func otCommand(ev *event.Event) (cmd, proto string) {
	if ev == nil || ev.Meta == nil {
		return "", ""
	}
	spec, ok := otCommandSpec[normalizeHandlerForProto(ev.Handler)]
	if !ok {
		return "", ""
	}
	v := metaDisplay(ev.Meta, spec.key)
	if v == "" && spec.alt != "" {
		v = metaDisplay(ev.Meta, spec.alt)
	}
	if v == "" {
		return "", ""
	}
	return v, spec.proto
}

// metaDisplay renders one meta value as a single display string: scalars via
// %v, string/any slices joined, "" when absent or empty. Long values are clipped
// so a stray large field can't blow out the table.
func metaDisplay(meta map[string]any, key string) string {
	v, ok := meta[key]
	if !ok || v == nil {
		return ""
	}
	var s string
	switch t := v.(type) {
	case string:
		s = t
	case []string:
		s = strings.Join(t, ", ")
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, fmt.Sprintf("%v", e))
		}
		s = strings.Join(parts, ", ")
	case bool:
		if !t {
			return ""
		}
		s = "yes"
	default:
		s = fmt.Sprintf("%v", t)
	}
	s = strings.TrimSpace(s)
	if len(s) > 2048 {
		s = s[:2048] + "…"
	}
	return s
}

// eventCommands gathers every command / query the attacker typed on an event —
// interactive-shell lines, SQL queries (mysql/postgres/mssql), Redis command
// chains, Mongo ops — into one ordered, de-duplicated list so the event-detail
// page can show "what they actually ran" as a clean sequence instead of an
// ugly map[...] blob in the generic meta table.
func eventCommands(ev *event.Event) []string {
	if ev == nil || ev.Meta == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, k := range eventCommandKeys {
		for _, c := range metaStrings(ev.Meta, k) {
			add(c)
		}
	}
	if c, _ := ev.Meta["exec_command"].(string); c != "" {
		add(c)
	}
	return out
}

// eventCommandKeys are the []string meta keys that hold attacker-typed command
// lines / queries. Kept here so both the gatherer and the meta-table excluder
// stay in sync.
var eventCommandKeys = []string{
	"shell_commands", "sql_queries", "pg_queries", "mssql_queries",
	"commands", "mongo_ops", "ldap_queries",
}

// labeledText is one named block of captured attacker content for the detail
// page (a staged payload body, a mail message, a dropper, …).
type labeledText struct {
	Label string
	Text  string
}

// eventBodies collects the larger free-text blobs an attacker transferred —
// staged payloads, mail bodies, deobfuscated droppers — so they render as
// readable blocks rather than one-line meta cells.
func eventBodies(ev *event.Event) []labeledText {
	if ev == nil || ev.Meta == nil {
		return nil
	}
	var out []labeledText
	for _, kv := range []struct{ key, label string }{
		{"redis_set_payload", "Redis staged payload (SET value)"},
		{"redis_drop_path", "Redis drop target path"},
		{"message_head", "SMTP message body"},
		{"bdat_chunk", "SMTP BDAT chunk"},
		{"deobfuscated", "Deobfuscated payload"},
		{"http_body", "HTTP request body"},
		{"post_body", "POST body"},
	} {
		if s, ok := ev.Meta[kv.key].(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, labeledText{Label: kv.label, Text: s})
		}
	}
	return out
}

// eventSecrets surfaces the attacker's OWN harvested secrets (secretscan) for
// the detail page: kind + a shape-preserving redaction, so the operator sees
// what was leaked without the full value shouting on screen.
func eventSecrets(ev *event.Event) []secretRow {
	if ev == nil || ev.Meta == nil {
		return nil
	}
	var out []secretRow
	for _, sc := range metaMapList(ev.Meta, "secrets") {
		kind, _ := sc["kind"].(string)
		val, _ := sc["value"].(string)
		if kind == "" || val == "" {
			continue
		}
		hint, _ := sc["hint"].(string)
		out = append(out, secretRow{Kind: kind, Redacted: redactSecret(val), Hint: hint})
	}
	return out
}

type secretRow struct {
	Kind     string
	Redacted string
	Hint     string
}

// redactSecret keeps a value's shape (prefix … suffix + length) so it is
// recognisable but not fully exposed in the UI.
func redactSecret(v string) string {
	if len(v) <= 10 {
		return strings.Repeat("•", len(v))
	}
	return v[:4] + "…" + v[len(v)-4:] + " (" + itoa(len(v)) + " chars)"
}
