package handler

// modbus_deep.go adds depth to the Modbus handler (shared by plaintext 502 and
// Modbus/TCP Security on 802): per-PDU intent + control/recon classification,
// register-reference / vendor-tag enrichment, vendor-specific function codes
// and the Schneider UMAS engineering channel, vendor "backdoor" / reserved-
// function and program/firmware-transfer detection, sensitive-area access, and
// session-level unit-id + function-code enumeration. Markers map to ATT&CK for
// ICS; the Schneider UMAS auth-bypass family carries CVE hits.

// modbusClassify enriches one PDU's meta and raises its intent + anomaly
// markers (replacing the inline switch the handler used previously).
func modbusClassify(entry map[string]any, res *Result) {
	fc, ok := entry["function_code"].(byte)
	if !ok {
		return
	}
	modbusEnrichRegister(fc, entry)

	switch {
	case fc == 0x5A: // Schneider UMAS engineering channel
		flagAnomaly(res, "modbus-umas")
		uname, _ := entry["umas_function"].(string)
		ucode, _ := entry["umas_function_code"].(byte)
		res.Meta["intent"] = "Schneider UMAS " + uname + " — unauthenticated engineering command"
		switch {
		case ucode == 0x40 || ucode == 0x41: // START/STOP PLC
			flagAnomaly(res, "ics-plc-mode-change")
		case ucode >= 0x21 && ucode <= 0x25: // WRITE memory/variables/registers
			flagAnomaly(res, "ics-plc-write")
		case ucode == 0x10: // take reservation (lock the PLC out of engineering)
			flagAnomaly(res, "modbus-umas-reservation")
		}
		// Schneider Modicon UMAS is unauthenticated by default — the bypass family.
		res.CVEHits = appendUnique(res.CVEHits, "CVE-2018-7842")
		flagAnomaly(res, "cve:CVE-2018-7842")

	case fc == 0x28 || fc == 0x29 || fc == 0x2A: // program / firmware transfer
		flagAnomaly(res, "modbus-program-download")
		flagAnomaly(res, "ics-plc-program-access")
		res.Meta["intent"] = "Modbus " + modbusFCName(fc) + " — PLC program/firmware transfer"

	case isVendorReservedFC(fc): // proprietary / undocumented function code
		flagAnomaly(res, "modbus-vendor-function")
		res.Meta["intent"] = "Modbus vendor/reserved function " + modbusFCName(fc) + " — proprietary/backdoor channel"

	case modbusIsWrite(fc):
		flagAnomaly(res, "modbus-write-attempt")
		res.Meta["intent"] = "Modbus " + modbusFCName(fc) + " — writing to a PLC (control manipulation)"

	case fc == 0x08: // Diagnostics
		if sub, ok := entry["diag_subfunction"].(uint16); ok {
			switch sub {
			case 0x0001, 0x0004: // restart comms / force listen-only
				flagAnomaly(res, "ics-modbus-diagnostic")
				res.Meta["intent"] = "Modbus Diagnostics — " + modbusDiagName(sub) + " (control/DoS)"
			case 0x000A, 0x000B, 0x000C, 0x000D, 0x000E, 0x000F, 0x0010, 0x0011, 0x0012:
				// clear counters / diagnostic registers — tampering with the
				// device's own telemetry (anti-forensics).
				flagAnomaly(res, "modbus-diagnostic-clear")
				setIfEmpty(res.Meta, "intent", "Modbus Diagnostics — clearing device counters/log")
			}
		}

	case fc == 0x2B:
		setIfEmpty(res.Meta, "intent", "Modbus Read Device Identification — PLC vendor/model fingerprinting")
	case fc == 0x11:
		setIfEmpty(res.Meta, "intent", "Modbus Report Server ID — device fingerprinting")
	case fc == 0x14:
		flagAnomaly(res, "ics-process-data-access")
		setIfEmpty(res.Meta, "intent", "Modbus Read File Record — reading device file/config")
	case fc == 0x07, fc == 0x0B, fc == 0x0C, fc == 0x18:
		setIfEmpty(res.Meta, "intent", "Modbus "+modbusFCName(fc)+" — device status/event recon")
	default:
		setIfEmpty(res.Meta, "intent", "Modbus "+modbusFCName(fc)+" — sampling registers/coils (recon)")
	}

	// Access to a vendor "system"/config register area is more than process
	// sampling — it's reading/writing device configuration.
	if modbusSensitiveAddr(entry) {
		flagAnomaly(res, "modbus-config-area-access")
	}
}

// modbusEnrichRegister stamps the Modicon reference number, the register class,
// and a vendor (Schneider IEC-61131) tag hint for the PDU's target address.
func modbusEnrichRegister(fc byte, entry map[string]any) {
	addr, ok := firstAddr(entry)
	if !ok {
		return
	}
	class, base, tag := "", 0, ""
	switch fc {
	case 0x01, 0x05, 0x0F: // coils
		class, base, tag = "coil", 1, "%M"
	case 0x02: // discrete inputs
		class, base, tag = "discrete-input", 100001, "%I"
	case 0x04: // input registers
		class, base, tag = "input-register", 300001, "%IW"
	case 0x03, 0x06, 0x10, 0x16, 0x17, 0x22, 0x23: // holding registers
		class, base, tag = "holding-register", 400001, "%MW"
	default:
		return
	}
	entry["register_class"] = class
	entry["register_ref"] = itoa(base + int(addr)) // Modicon 0/1/3/4xxxx reference
	entry["tag_hint"] = tag + itoa(int(addr))      // Schneider/IEC %MW-style tag
}

// firstAddr returns the target address captured for the PDU (start/reg/coil).
func firstAddr(entry map[string]any) (uint16, bool) {
	for _, k := range []string{"start_addr", "reg_addr", "coil_addr", "write_addr"} {
		if v, ok := entry[k].(uint16); ok {
			return v, true
		}
	}
	return 0, false
}

// modbusSensitiveAddr reports whether the PDU targets a vendor "system" /
// configuration register window rather than the process image. Schneider maps
// system words (%SW) high in the holding range, and many vendors place
// firmware/config in the top of the address space; access there is config
// tampering, not control-loop sampling.
func modbusSensitiveAddr(entry map[string]any) bool {
	addr, ok := firstAddr(entry)
	if !ok {
		return false
	}
	class, _ := entry["register_class"].(string)
	// Top-of-range holding registers (>= 0xEF00) or the classic system-word
	// window (0xC000..0xC0FF) are the config/system areas.
	return class == "holding-register" && (addr >= 0xEF00 || (addr >= 0xC000 && addr <= 0xC0FF))
}

// isVendorReservedFC reports whether a function code is a vendor-defined /
// reserved one (Modbus reserves 65-72 and 100-110 for vendor use; several
// vendors use these for proprietary engineering "backdoor" access).
func isVendorReservedFC(fc byte) bool {
	return (fc >= 0x41 && fc <= 0x48) || (fc >= 0x64 && fc <= 0x6E)
}

// modbusSessionAnalysis runs after all PDUs are processed and flags session-
// level enumeration: scanning many unit-ids (slave/unit sweep), exercising many
// distinct function codes (FC scan), or addressing unit 0 with a write
// (broadcast write to every slave).
func modbusSessionAnalysis(pdus []map[string]any, res *Result) {
	units := map[byte]struct{}{}
	fcs := map[byte]struct{}{}
	for _, e := range pdus {
		if u, ok := e["unit_id"].(byte); ok {
			units[u] = struct{}{}
			if u == 0 {
				if fc, ok := e["function_code"].(byte); ok && modbusIsWrite(fc) {
					flagAnomaly(res, "modbus-broadcast-write")
				}
			}
		}
		if fc, ok := e["function_code"].(byte); ok {
			fcs[fc] = struct{}{}
		}
	}
	if len(units) >= 4 {
		flagAnomaly(res, "modbus-uid-enumeration")
		res.Meta["modbus_units_seen"] = len(units)
	}
	if len(fcs) >= 5 {
		flagAnomaly(res, "modbus-fc-scan")
		res.Meta["modbus_fcs_seen"] = len(fcs)
	}
}
